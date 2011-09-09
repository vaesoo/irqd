# spec file for irqd

# norootforbuild

Name:           irqd
License:        GPL v2 or later
Summary:        IRQ Balancer
Version:        0.6.1
Release:        1.%{_gitrelease}
AutoReqProv:    on
BuildRequires:  pkg-config libnl-devel glib2-devel
Source0:        %{name}.git.tar.gz
Source1:        rc.irqd
Source2:        selfmon.irqd
Source99:	    gitinfo
Group:          System/Monitoring
Provides:	    %{_gitprovides}
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Conflicts:      irqbalance

%description
Alternative IRQ balancer.

%prep
%setup -n %{name}

%build
make %{?jobs:-j%jobs} OPTFLAGS="$RPM_OPT_FLAGS"

%install 
%makeinstall
install -m 755 %SOURCE1 -D $RPM_BUILD_ROOT/etc/init.d/irqd
install -m 644 %SOURCE2 -D $RPM_BUILD_ROOT/etc/selfmonng.d/irqd.check
mkdir -p $RPM_BUILD_ROOT/etc/init.d/rc3.d
ln -s ../irqd $RPM_BUILD_ROOT/etc/init.d/rc3.d/S05irqd
ln -s ../irqd $RPM_BUILD_ROOT/etc/init.d/rc3.d/K40irqd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr (-,root,root,755)
/usr/sbin/irqd
/etc/init.d/irqd
/etc/selfmonng.d/irqd.check
%config /etc/init.d/rc3.d/S05irqd
%config /etc/init.d/rc3.d/K40irqd

%changelog
* Tue Apr 12 2011 - heitzenberger@astaro.com
- initial

