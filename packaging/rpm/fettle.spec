# fettle — RPM spec for the RHEL family (RHEL/Rocky/Alma/CentOS Stream) and Fedora.
#
# Built by packaging/rpm/build.sh, which makes the source tarball this expects. The
# %install step calls packaging/install.sh, the same script the .deb and the Arch
# package use, so all three ship the identical layout.

Name:           fettle
Version:        %{_fettle_version}
Release:        1%{?dist}
Summary:        Cross-distribution Linux maintenance and supply-chain tool

License:        MIT
URL:            https://github.com/pasadoorian/fettle
Source0:        %{name}-%{version}.tar.gz

# Pure python, no compiled anything — one package serves every architecture.
BuildArch:      noarch
BuildRequires:  python3
# RHEL/Rocky/Alma 9 ship python3 = 3.9 with python3.11 available in appstream, while
# Fedora's python3 is already newer than 3.11. A plain `python3 >= 3.11` would therefore
# refuse to install on the entire EL9 family — a platform fettle supports and has a
# backend for. The boolean form (rpm 4.13+; EL9 has 4.16) is satisfied by whichever is
# true, and pulls in python3.11 when neither is.
Requires:       (python3 >= 3.11 or python3.11 or python3.12 or python3.13)

%description
One command surface keeps a machine updated and clean, audits where its software
came from and whether it has been tampered with, and scans the firmware and boot
chain.

Pure standard library: it needs python3 and nothing else.

%prep
%setup -q

%install
sh packaging/install.sh %{buildroot} %{_prefix}

# %%{_libdir} is /usr/lib64 on x86_64, and this package is noarch python that belongs in
# /usr/lib — so the path is spelled out rather than macro'd, and matches what
# install.sh actually created.
%files
%{_bindir}/fettle
%{_prefix}/lib/fettle
%{_datadir}/bash-completion/completions/fettle
%{_datadir}/doc/fettle

%changelog
# Release notes live in CHANGELOG.md; duplicating them here would be a second copy to
# forget to update. rpmbuild does not require this section to be populated.
