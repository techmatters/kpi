export const ROOT_BREADCRUMBS = new Map([
  [
    'projects', {
      label: t('Projects'),
      href: '#/forms'
    }
  ],
  [
    'my-library', {
      label: t('My Library'),
      href: '#/library/my-library'
    }
  ],
  [
    'public-collections', {
      label: t('Public Collections'),
      href: '#/library/public-collections'
    }
  ],
]);

export const ASSETS_TABLE_CONTEXTS = {};
new Set([
  'MY_LIBRARY',
  'COLLECTION_CONTENT',
  'PUBLIC_COLLECTIONS',
]).forEach((name) => {ASSETS_TABLE_CONTEXTS[name] = name;});
Object.freeze(ASSETS_TABLE_CONTEXTS);

export const ORDER_DIRECTIONS = {};
new Set([
  'ascending',
  'descending',
]).forEach((name) => {ORDER_DIRECTIONS[name] = name;});
Object.freeze(ORDER_DIRECTIONS);

/**
 * @typedef AssetsTableColumn
 * @prop {string} label
 * @prop {string} id
 * @prop {string} [filterBy] - a backend filter property
 * @prop {string} [filterByPath] - a path to asset property that holds the data
 * @prop {string} [filterByMetadataName] - name of the metadata property that holds the values for the filter
 * @prop {string} [orderBy] - a backend order property
 * @prop {boolean} [defaultValue]
 */
export const ASSETS_TABLE_COLUMNS = Object.freeze({
  'icon-status': {
    label: t('Type'),
    id: 'icon-status',
    orderBy: 'asset_type',
    defaultValue: ORDER_DIRECTIONS.ascending,
  },
  'date-modified': {
    label: t('Last Modified'),
    id: 'date-modified',
    orderBy: 'date_modified',
    defaultValue: ORDER_DIRECTIONS.descending,
  },
  name: {
    label: t('Name'),
    id: 'name',
    orderBy: 'name',
    defaultValue: ORDER_DIRECTIONS.ascending,
  },
  'items-count': {
    label: t('Items'),
    id: 'items-count',
    // TODO: currently it is not possible to order by summary.row_count and children.count at the same time
    // so we disable this column
    orderBy: null,
    defaultValue: null,
  },
  owner: {
    label: t('Owner'),
    id: 'owner',
    orderBy: 'owner__username',
    defaultValue: ORDER_DIRECTIONS.ascending,
  },
  'subscribers-count': {
    label: t('Subscribers'),
    id: 'subscribers-count',
    orderBy: 'subscribers_count',
    defaultValue: ORDER_DIRECTIONS.ascending,
  },
  languages: {
    label: t('Languages'),
    id: 'languages',
    filterBy: 'summary__languages__icontains',
    filterByPath: ['summary', 'languages'],
    filterByMetadataName: 'languages',
  },
  'primary-sector': {
    label: t('Primary Sector'),
    id: 'primary-sector',
    filterBy: 'settings__sector__value',
    filterByPath: ['settings', 'sector'],
    filterByMetadataName: 'sectors',
  },
});
