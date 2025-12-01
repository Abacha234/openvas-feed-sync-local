# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4376");
  script_cve_id("CVE-2025-4748", "CVE-2025-48038", "CVE-2025-48039", "CVE-2025-48041");
  script_tag(name:"creation_date", value:"2025-11-25 04:09:05 +0000 (Tue, 25 Nov 2025)");
  script_version("2025-11-25T05:40:35+0000");
  script_tag(name:"last_modification", value:"2025-11-25 05:40:35 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-4376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4376-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4376-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'erlang' package(s) announced via the DLA-4376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'erlang' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dev", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-doc", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-et", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-examples", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ftp", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-inets", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mode", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-nox", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-observer", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-src", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tftp", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tools", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-wx", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-x11", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:23.2.6+dfsg-1+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
