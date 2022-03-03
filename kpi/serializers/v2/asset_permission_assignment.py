# coding: utf-8
from collections import defaultdict

from django.contrib.auth.models import Permission, User
from django.urls import Resolver404
from django.utils.translation import gettext as t
from rest_framework import serializers
from rest_framework.fields import empty
from rest_framework.reverse import reverse


from kpi.constants import (
    PERM_PARTIAL_SUBMISSIONS,
    PREFIX_PARTIAL_PERMS,
    SUFFIX_SUBMISSIONS_PERMS,
)
from kpi.fields.relative_prefix_hyperlinked_related import (
    RelativePrefixHyperlinkedRelatedField,
)
from kpi.models.asset import Asset
from kpi.models.object_permission import ObjectPermission
from kpi.utils.object_permission import (
    get_user_permission_assignments_queryset,
)
from kpi.utils.urls import absolute_resolve


class AssetPermissionAssignmentSerializer(serializers.ModelSerializer):

    url = serializers.SerializerMethodField()
    user = RelativePrefixHyperlinkedRelatedField(
        view_name='user-detail',
        lookup_field='username',
        queryset=User.objects.all(),
        style={'base_template': 'input.html'}  # Render as a simple text box
    )
    permission = RelativePrefixHyperlinkedRelatedField(
        view_name='permission-detail',
        lookup_field='codename',
        queryset=Permission.objects.all(),
        style={'base_template': 'input.html'}  # Render as a simple text box
    )
    partial_permissions = serializers.SerializerMethodField()
    label = serializers.SerializerMethodField()

    class Meta:
        model = ObjectPermission
        fields = (
            'url',
            'user',
            'permission',
            'partial_permissions',
            'label',
        )

        read_only_fields = ('uid', 'label')

    def create(self, validated_data):
        user = validated_data['user']
        asset = validated_data['asset']
        if asset.owner_id == user.id:
            raise serializers.ValidationError({
                'user': "Owner's permissions cannot be assigned explicitly"})
        permission = validated_data['permission']
        partial_permissions = validated_data.get('partial_permissions', None)

        bulk = self.context.get('bulk', False)
        # When bulk is `True`, the `from_kc_only` flag is removed from *all*
        # users prior to calling this method. There is no need to remove it
        # again from each user individually. See
        # `AssetPermissionAssignmentViewSet.bulk_assignments()`
        # TODO: Remove after kobotoolbox/kobocat#642
        if bulk is False and asset.has_deployment:
            asset.deployment.remove_from_kc_only_flag(specific_user=user)

        return asset.assign_perm(user, permission.codename,
                                 partial_perms=partial_permissions)

    def get_label(self, object_permission):
        # `self.object_permission.label` calls `self.object_permission.asset`
        # internally. Thus, costs an extra query each time the object is
        # serialized. `asset` is already loaded and attached to context,
        # let's use it!
        try:
            asset = self.context['asset']
        except KeyError:
            return object_permission.label
        else:
            return asset.get_label_for_permission(
                object_permission.permission.codename
            )

    def get_partial_permissions(self, object_permission):
        codename = object_permission.permission.codename
        if codename.startswith(PREFIX_PARTIAL_PERMS):
            view = self.context.get('view')
            # if view doesn't have an `asset` property,
            # fallback to context. (e.g. AssetViewSet)
            asset = getattr(view, 'asset', self.context.get('asset'))
            partial_perms = asset.get_partial_perms(
                object_permission.user_id, with_filters=True)
            if not partial_perms:
                return None

            if partial_perms:
                hyperlinked_partial_perms = []
                for perm_codename, filters in partial_perms.items():
                    url = self.__get_permission_hyperlink(perm_codename)
                    hyperlinked_partial_perms.append({
                        'url': url,
                        'filters': filters
                    })
                return hyperlinked_partial_perms
        return None

    def get_url(self, object_permission):
        asset_uid = self.context.get('asset_uid')
        return reverse('asset-permission-assignment-detail',
                       args=(asset_uid, object_permission.uid),
                       request=self.context.get('request', None))

    def validate(self, attrs):
        # Because `partial_permissions` is a `SerializerMethodField`,
        # it's read-only, so it's not validated nor added to `validated_data`.
        # We need to do it manually
        self.validate_partial_permissions(attrs)
        return attrs

    def validate_partial_permissions(self, attrs):
        """
        Validates permissions and filters sent with partial permissions.

        If data is valid, `partial_permissions` attribute is added to `attrs`.
        Useful to permission assignment in `create()`.

        :param attrs: dict of `{'user': '<username>',
                                'permission': <permission object>}`
        :return: dict, the `attrs` parameter updated (if necessary) with
                 validated `partial_permissions` dicts.
        """
        permission = attrs['permission']
        if not permission.codename.startswith(PREFIX_PARTIAL_PERMS):
            # No additional validation needed
            return attrs

        def _invalid_partial_permissions(message):
            raise serializers.ValidationError(
                {'partial_permissions': message}
            )

        request = self.context['request']
        partial_permissions = None

        if isinstance(request.data, dict):  # for a single assignment
            partial_permissions = request.data.get('partial_permissions')
        elif self.context.get('partial_permissions'):  # injected during bulk assignment
            partial_permissions = self.context.get('partial_permissions')

        if not partial_permissions:
            _invalid_partial_permissions(
                t("This field is required for the '{}' permission").format(
                    permission.codename
                )
            )

        partial_permissions_attr = defaultdict(list)

        for partial_permission, filters_ in \
                self.__get_partial_permissions_generator(partial_permissions):
            try:
                resolver_match = absolute_resolve(
                    partial_permission.get('url')
                )
            except (TypeError, Resolver404):
                _invalid_partial_permissions(t('Invalid `url`'))

            try:
                codename = resolver_match.kwargs['codename']
            except KeyError:
                _invalid_partial_permissions(t('Invalid `url`'))

            # Permission must valid and must be assignable.
            if not self._validate_permission(codename,
                                             SUFFIX_SUBMISSIONS_PERMS):
                _invalid_partial_permissions(t('Invalid `url`'))

            # No need to validate Mongo syntax, query will fail
            # if syntax is not correct.
            if not isinstance(filters_, dict):
                _invalid_partial_permissions(t('Invalid `filters`'))

            # Validation passed!
            partial_permissions_attr[codename].append(filters_)

        # Everything went well. Add it to `attrs`
        attrs.update({'partial_permissions': partial_permissions_attr})

        return attrs

    def validate_permission(self, permission):
        """
        Checks if permission can be assigned on asset.
        """
        if not self._validate_permission(permission.codename):
            raise serializers.ValidationError(
                t(
                    '{permission} cannot be assigned explicitly to '
                    'Asset objects of this type.'
                ).format(permission=permission.codename)
            )
        return permission

    def to_representation(self, instance):
        """
        Doesn't display 'partial_permissions' attribute if it's `None`.
        """
        try:
            # Each time we try to access `instance.label`, `instance.content_object`
            # is needed. Django can't find it from objects cache even if it already
            # exists. Because of `GenericForeignKey`, `select_related` can't be
            # used to load it within the same queryset. So Django hits DB each
            # time a label is shown. `prefetch_related` helps, but not that much.
            # It still needs to load object from DB at least once.
            # It means, when listing assets, it would add as many extra queries
            # as assets. `content_object`, in that case, is the parent asset and
            # we can access it through the context. Let's use it.
            asset = self.context['asset']
            setattr(instance, 'content_object', asset)
        except KeyError:
            pass

        repr_ = super().to_representation(instance)
        repr_copy = dict(repr_)
        for k, v in repr_copy.items():
            if k == 'partial_permissions' and v is None:
                del repr_[k]

        return repr_

    def _validate_permission(self, codename, suffix=None):
        """
        Validates if `codename` can be assigned on `Asset`s.
        Search can be restricted to assignable codenames which end with `suffix`

        :param codename: str. See `Asset.ASSIGNABLE_PERMISSIONS
        :param suffix: str.
        :return: bool.
        """
        return (
            # DONOTMERGE abusive to the database server?
            codename in Asset.objects.only('asset_type').get(
                uid=self.context['asset_uid']
            ).get_assignable_permissions(
                with_partial=True
            ) and (suffix is None or codename.endswith(suffix))
        )

    def __get_partial_permissions_generator(self, partial_permissions):
        """
        Creates a generator to iterate over partial_permissions list.
        Useful to validate each item and stop iterating as soon as errors
        are detected

        :param partial_permissions: list
        :return: generator
        """
        for partial_permission in partial_permissions:
            for filters_ in partial_permission.get('filters'):
                yield partial_permission, filters_

    def __get_permission_hyperlink(self, codename):
        """
        Builds permission hyperlink representation.
        :param codename: str
        :return: str. url
        """
        return reverse('permission-detail',
                       args=(codename,),
                       request=self.context.get('request', None))


class AssetBulkInsertPermissionSerializer(AssetPermissionAssignmentSerializer):

    class Meta:
        model = ObjectPermission
        fields = (
            'user',
            'permission',
        )


class PartialPermissionField(serializers.Field):
    default_error_messages = {
        'invalid': t('Not a valid list.'),
        'blank': t('This field may not be blank.'),
    }
    initial = ''

    def __init__(self, **kwargs):
        super().__init__(required=False, **kwargs)

    def to_internal_value(self, data):
        # We're lenient with allowing basic numerics to be coerced into strings,
        # but other types should fail. Eg. unclear if booleans should represent as `true` or `True`,
        # and composites such as lists are likely user error.
        if not isinstance(data, list):
            self.fail('invalid')
        return data

    def to_representation(self, value):
        return value


class PermissionAssignmentSerializer(serializers.Serializer):

    user = serializers.CharField()
    permission = serializers.CharField()
    partial_permissions = PartialPermissionField()


class BulkPermissionAssignmentSerializer(serializers.Serializer):

    assignments = serializers.ListField(child=PermissionAssignmentSerializer())

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance=instance, data=data, **kwargs)
        self._assignments = []

    def create(self, validated_data):

        request = self.context['request']
        asset = self.context['asset']

        new_assignments = validated_data['assignments']
        new_assignments_by_user = defaultdict(list)
        searchable_new_assigns = []

        for new_assignment in new_assignments:
            new_assignments_by_user[new_assignment['user'].pk].append(new_assignment)
            searchable_new_assigns.append((
                new_assignment['user'].pk,
                new_assignment['permission'].pk,
            ))

        old_assignments = list(
            get_user_permission_assignments_queryset(
                asset, request.user
            ).exclude(user=asset.owner)
        )

        old_assign_idxs_to_del = []

        for old_assign_idx, old_assign in enumerate(old_assignments):
            try:
                new_assign_idx = searchable_new_assigns.index(
                    (old_assign.user_id, old_assign.permission_id)
                )
            except ValueError:
                # An old assignment that has been removed
                old_assign_idxs_to_del.append(old_assign_idx)
            else:
                # An old assignment that should be kept; remove from list of
                # potential new assignments to search and add
                # …unless it's a partial permission; unconditionally re-assign
                # those to avoid diffing them

                if (
                    new_assignments[new_assign_idx]['permission'].codename
                    != PERM_PARTIAL_SUBMISSIONS
                ):
                    del new_assignments[new_assign_idx]
                    del searchable_new_assigns[new_assign_idx]

        # let's do the removals first
        # …in case they remove something implied by a new assignment (?)
        users_to_redo = set()
        for del_idx in old_assign_idxs_to_del:
            perm = old_assignments[del_idx]
            print('---', perm, flush=True)
            users_to_redo.add(perm.user.pk)
            asset.remove_perm(perm.user, perm.permission.codename)

        # ToDo Bulk delete

        for ser in new_assignments:
            if ser['user'].pk in users_to_redo:
                # gonna have to deal with you later anyway
                continue

            print('SER', ser, flush=True)
            perm = asset.assign_perm(
                user_obj=ser['user'],
                perm=ser['permission'].codename,
                partial_perms=ser.get('partial_permissions'),
            )
            print('+++', perm)

        # whoops, you had manage and got reduced to change
        # the BE had manage, change, view
        # the FE sent change
        # we removed manage and view but added nothin'
        #
        # ideas…
        # do all deletions, then re-query db?
        # do a per-user diff?

        # how about: re-add all extant perms for users who had deletions
        for user_id in users_to_redo:
            extant_assigns = new_assignments_by_user[user_id]
            for serializer in extant_assigns:
                perm = asset.assign_perm(
                    user_obj=serializer['user'],
                    perm=serializer['permission'].codename,
                    partial_perms=serializer.get('partial_permissions'),
                )
                print('++++++', perm, flush=True)

        return new_assignments

    def validate(self, attrs):
        usernames = []
        codenames = []
        partial_codenames = []
        for assignment in attrs['assignments']:
            codename = self._get_permission_codename(assignment['permission'])
            codenames.append(codename)
            if codename == PERM_PARTIAL_SUBMISSIONS:
                for partial_assignment in assignment['partial_permissions']:
                    partial_codenames.append(
                        self._get_permission_codename(partial_assignment['url'])
                    )

            usernames.append(self._get_username(assignment['user']))

        self._validate_codenames(partial_codenames, suffix=SUFFIX_SUBMISSIONS_PERMS)
        users = self._validate_usernames(usernames)
        permissions = self._validate_codenames(codenames)

        assert len(codenames) == len(usernames) == len(attrs['assignments'])

        assignment_objects = []
        for idx, assignment in enumerate(attrs['assignments']):
            assignment_object = {
                'user': self._get_object(usernames[idx], users, 'username'),
                'permission': self._get_object(codenames[idx], permissions, 'codename')
            }
            if codenames[idx] == PERM_PARTIAL_SUBMISSIONS:
                assignment_object['partial_permissions'] = defaultdict(list)
                for partial_perms in assignment['partial_permissions']:
                    partial_codename = partial_codenames.pop(0)
                    assignment_object['partial_permissions'][
                        partial_codename
                    ] = partial_perms['filters']

            assignment_objects.append(assignment_object)

        attrs['assignments'] = assignment_objects

        return attrs

    def _get_permission_codename(self, permission_url: str) -> str:
        try:
            resolver_match = absolute_resolve(permission_url)
            codename = resolver_match.kwargs['codename']
        except (TypeError, KeyError, Resolver404):
            raise serializers.ValidationError(
                t('Invalid permission: `## permission_url ##`').format(
                    {'## permission_url ##': permission_url}
                )
            )

        return codename

    def _get_username(self, user_url: str) -> str:
        try:
            resolver_match = absolute_resolve(user_url)
            username = resolver_match.kwargs['username']
        except (TypeError, KeyError, Resolver404):
            raise serializers.ValidationError(
                t('Invalid user: `## user_url ##`').format(
                    {'## user_url ##': user_url}
                )
            )

        return username

    def _validate_codenames(self, codenames: list, suffix: str = None) -> list:
        asset = self.context['asset']
        codenames = set(codenames)
        assignable_permissions = asset.get_assignable_permissions(
            with_partial=True
        )
        diff = codenames.difference(assignable_permissions)
        if diff:
            raise serializers.ValidationError('ERREUR CODENAMES')

        if suffix:
            return

        return Permission.objects.filter(codename__in=codenames)

    def _validate_usernames(self, usernames: list) -> list:
        usernames = set(usernames)
        users = list(User.objects.filter(username__in=usernames))
        if len(users) != len(usernames):
            raise serializers.ValidationError('ERREUR USERS')

        return users

    def _get_object(self, value, object_list, fieldname):
        for obj in object_list:
            if value == getattr(obj, fieldname):
                return obj
