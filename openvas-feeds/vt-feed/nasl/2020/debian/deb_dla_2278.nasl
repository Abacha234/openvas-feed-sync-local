# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892278");
  script_cve_id("CVE-2018-19132", "CVE-2019-12519", "CVE-2019-12520", "CVE-2019-12521", "CVE-2019-12523", "CVE-2019-12524", "CVE-2019-12525", "CVE-2019-12526", "CVE-2019-12528", "CVE-2019-12529", "CVE-2019-13345", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679", "CVE-2019-18860", "CVE-2020-11945", "CVE-2020-8449", "CVE-2020-8450");
  script_tag(name:"creation_date", value:"2020-07-17 12:33:38 +0000 (Fri, 17 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-17 12:40:00 +0000 (Wed, 17 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-2278)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2278");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2278-3");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/squid3");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DLA-2278 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The update of squid3 released as DLA-2278-2 introduced a regression due to the updated fix for CVE-2019-12529. The new Kerberos authentication code prevented base64 token negotiation. Updated squid3 packages are now available to correct this issue.

For Debian 9 stretch, this problem has been fixed in version 3.5.23-5+deb9u4.

We recommend that you upgrade your squid3 packages.

For the detailed security status of squid3 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);