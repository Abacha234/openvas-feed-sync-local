# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891495");
  script_cve_id("CVE-2017-12976", "CVE-2018-10857", "CVE-2018-10859");
  script_tag(name:"creation_date", value:"2018-09-05 22:00:00 +0000 (Wed, 05 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 10:29:00 +0000 (Thu, 06 Sep 2018)");

  script_name("Debian: Security Advisory (DLA-1495)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1495");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1495");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git-annex' package(s) announced via the DLA-1495 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The git-annex package was found to have multiple vulnerabilities when operating on untrusted data that could lead to arbitrary command execution and encrypted data exfiltration.

CVE-2017-12976

git-annex before 6.20170818 allows remote attackers to execute arbitrary commands via an ssh URL with an initial dash character in the hostname, as demonstrated by an ssh://-eProxyCommand= URL, a related issue to CVE-2017-9800, CVE-2017-12836, CVE-2017-1000116, and CVE-2017-1000117.

CVE-2018-10857

git-annex is vulnerable to a private data exposure and exfiltration attack. It could expose the content of files located outside the git-annex repository, or content from a private web server on localhost or the LAN.

CVE-2018-10859

git-annex is vulnerable to an Information Exposure when decrypting files. A malicious server for a special remote could trick git-annex into decrypting a file that was encrypted to the user's gpg key. This attack could be used to expose encrypted data that was never stored in git-annex

For Debian 8 Jessie, these problems have been fixed in version 5.20141125+oops-1+deb8u2.

We recommend that you upgrade your git-annex packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'git-annex' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);