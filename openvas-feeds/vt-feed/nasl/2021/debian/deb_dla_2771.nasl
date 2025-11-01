# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892771");
  script_cve_id("CVE-2018-20217", "CVE-2018-5710", "CVE-2018-5729", "CVE-2018-5730", "CVE-2021-37750");
  script_tag(name:"creation_date", value:"2021-10-01 01:00:25 +0000 (Fri, 01 Oct 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 12:11:00 +0000 (Mon, 18 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-2771)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2771");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2771");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/krb5");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DLA-2771 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in MIT Kerberos, a system for authenticating users and services on a network.

CVE-2018-5729

CVE-2018-5730

Fix flaws in LDAP DN checking.

CVE-2018-20217

Ignore password attributes for S4U2Self requests.

CVE-2021-37750

Fix KDC null deref on TGS inner body null server.

For Debian 9 stretch, these problems have been fixed in version 1.15-1+deb9u3.

We recommend that you upgrade your krb5 packages.

For the detailed security status of krb5 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);