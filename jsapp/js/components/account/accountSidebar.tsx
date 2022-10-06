import React from 'react';
import {ROUTES} from 'js/router/routerConstants';
import bem from 'js/bem';
import LoadingSpinner from 'js/components/common/loadingSpinner';
import Icon from 'js/components/common/icon';
import './accountSidebar.scss';
import envStore from 'js/envStore';

interface AccountSidebarProps {
  submissionsPerMonth: number;
  /* TODO: Placeholder from mockups, naming and typing subject to change
    dataStoreage: any,
    transcriptionMinutes: any,
	  machineTranslation: any,
	*/
}

interface AccountSidebarState {
	isLoading: boolean;
}

export default class AccountSidebar extends React.Component<
  AccountSidebarProps,
  AccountSidebarState
> {
  constructor(props: AccountSidebarProps) {
    super(props);
    this.state = {
      isLoading: true,
    };
  }

  componentDidMount() {
    this.setState({
      isLoading: false,
    });
  }

  isAccountSelected(): boolean {
    return (
      location.hash.split('#')[1] === ROUTES.ACCOUNT_SETTINGS
    );
  }

  isDataStorageSelected(): boolean {
    return location.hash.split('#')[1] === ROUTES.DATA_STORAGE;
  }

  isSecuritySelected(): boolean {
    return location.hash.split('#')[1] === ROUTES.SECURITY;
  }

  render() {
    const sidebarModifier = 'account';

    if (this.state.isLoading) {
      return <LoadingSpinner />;
    } else {
      return (
        <bem.FormSidebar m={sidebarModifier}>
          <bem.FormSidebar__label
            m={{selected: this.isAccountSelected()}}
            href={'#' + ROUTES.ACCOUNT_SETTINGS}
          >
            <Icon name='user' size='xl'/>
            <bem.FormSidebar__labelText>
              {t('Profile')}
            </bem.FormSidebar__labelText>
          </bem.FormSidebar__label>

        {/* TEMP hide tab. */}
          {false &&
          <bem.FormSidebar__label
            m={{selected: this.isDataStorageSelected()}}
            href={'#' + ROUTES.DATA_STORAGE}
            disabled
          >
            {/*TODO: get the data usage icon*/}
            <Icon name='projects' size='xl'/>
            <bem.FormSidebar__labelText>
              {t('Data storage')}
            </bem.FormSidebar__labelText>
          </bem.FormSidebar__label>
          }

          { /* hide "Security" entirely if nothing there is available */
            envStore.isReady && envStore.data.mfa_enabled &&
            <bem.FormSidebar__label
              m={{selected: this.isSecuritySelected()}}
              href={'#' + ROUTES.SECURITY}
              disabled={ !(envStore.isReady && envStore.data.mfa_enabled) }
            >
              <Icon name='lock-alt' size='xl'/>
              <bem.FormSidebar__labelText>
                {t('Security')}
              </bem.FormSidebar__labelText>
            </bem.FormSidebar__label>
          }
        </bem.FormSidebar>
      );
    }
  }
}
