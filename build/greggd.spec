%global gitversion %(git describe --tags --abbrev=0)
%global gitrelease %(git rev-parse --short HEAD)
%define debug_package %{nil}
Name:		greggd
Version:	%{gitversion}
Release:	%{gitrelease}%{?dist}
Summary:	Global runtime for eBPF-enabled gathering (w/ gumption) daemon

License:	ASL 2.0
URL:		https://github.com/olcf/%{name}
Source0:	https://github.com/olcf/%{name}/release/%{name}-%{gitversion}-%{gitrelease}.tar.gz

BuildRequires:	golang
BuildRequires:	bcc
BuildRequires:	bcc-devel
BuildRequires:	git
Requires:	 bcc

%description
System daemon wrapping the BPF Compiler Collection to compile and load BPF
programs into the kernel, and output data to metric reporting tools via a
unix-socket.

%prep
%setup -q -c %{name}-%{gitversion}-%{gitrelease}

%build
make build

%install
make DESTDIR=%{buildroot} PREFIX=%{_prefix} install

%files
%{_prefix}/sbin/%{name}
%{_prefix}/lib/systemd/system/%{name}.service
%{_prefix}/share/%{name}/c/
%doc %{_prefix}/share/%{name}/doc/

%changelog
