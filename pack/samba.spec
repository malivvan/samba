Name:           samba
Version:        1.4.0
Release:        1%{?dist}
Summary:        Pure-Go SMB2/SMB3 file server (zero-copy reads, multichannel)
License:        MIT
URL:            https://github.com/malivvan/samba
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  golang >= 1.27
Requires:       systemd

%description
A from-scratch SMB2/SMB3 file server written entirely in Go (no CGO, no
unsafe). It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 authentication, SMB2/3
signing, SMB 3.1.1 preauth integrity, SMB3
multichannel, and SMB3 encryption (AES-128/256-GCM and -CCM), plus byte-range
locks, leases, and directory change notification. Large unsigned reads move
file pages to the socket through splice(2) without entering userspace, and
every host facility it needs is native on Linux (the same source also builds
for macOS, the BSDs and Windows).

%prep
%setup -q

%build
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o samba ./cmd

%install
install -Dpm0755 samba %{buildroot}%{_bindir}/samba
install -Dpm0644 samba.toml.example %{buildroot}%{_sysconfdir}/samba/samba.toml
install -Dpm0644 pack/samba.service %{buildroot}%{_unitdir}/samba.service
install -Dpm0644 docs/samba.8 %{buildroot}%{_mandir}/man8/samba.8
install -Dpm0644 README.md %{buildroot}%{_docdir}/samba/README.md
install -Dpm0644 SECURITY.md %{buildroot}%{_docdir}/samba/SECURITY.md

%post
%systemd_post samba.service

%preun
%systemd_preun samba.service

%postun
%systemd_postun_with_restart samba.service

%files
%license LICENSE
%doc README.md SECURITY.md
%{_bindir}/samba
%{_unitdir}/samba.service
%{_mandir}/man8/samba.8*
%config(noreplace) %{_sysconfdir}/samba/samba.toml

%changelog
* Mon Oct 05 2026 malivvan <malivvan@users.noreply.github.com> - 1.4.0-1
- Initial package: pure-Go SMB2/SMB3 file server at the 1.4 feature level.
