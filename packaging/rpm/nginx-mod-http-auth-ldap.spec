# Built by packaging/build-rpm.sh, which defines upstream_version and
# pkg_release and appends the %changelog entry.

Name:           nginx-mod-http-auth-ldap
Version:        %{upstream_version}
Release:        %{pkg_release}%{?dist}
Summary:        LDAP authentication module for nginx
License:        BSD-2-Clause
URL:            https://github.com/kvspb/nginx-auth-ldap
Source0:        nginx-auth-ldap-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  nginx-mod-devel
BuildRequires:  openldap-devel
# nginx(abi) = <version> is added by the nginxmods file attribute of
# nginx-mod-devel.

%description
Checks HTTP Basic credentials against LDAP servers: finds the user DN,
checks require user / require group rules, binds as the user to verify the
password, and caches the results. Supports ldap://, ldaps://, StartTLS and
ldapi://, several servers with failover, and passes the DN and attributes
of the user on in variables.

%prep
%autosetup -n nginx-auth-ldap-%{version}

%build
# The macro configures with --with-compat alone; without
# --with-http_ssl_module the module is built without TLS.
%nginx_modconfigure --with-http_ssl_module
%nginx_modbuild

%install
install -Dpm 0755 %{_vpath_builddir}/ngx_http_auth_ldap_module.so \
    %{buildroot}%{nginx_moddir}/ngx_http_auth_ldap_module.so
install -dm 0755 %{buildroot}%{nginx_modconfdir}
echo 'load_module "%{nginx_moddir}/ngx_http_auth_ldap_module.so";' \
    >%{buildroot}%{nginx_modconfdir}/mod-http-auth-ldap.conf

%files
%license LICENSE
%doc README.md CHANGELOG.md example.conf
%{nginx_moddir}/ngx_http_auth_ldap_module.so
%{nginx_modconfdir}/mod-http-auth-ldap.conf

%changelog
