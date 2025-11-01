# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891674");
  script_cve_id("CVE-2018-1000888");
  script_tag(name:"creation_date", value:"2019-02-11 23:00:00 +0000 (Mon, 11 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-15 18:15:00 +0000 (Mon, 15 Jun 2020)");

  script_name("Debian: Security Advisory (DLA-1674)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1674");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1674");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DLA-1674 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"php-pear in php5 contains CWE-502 (Deserialization of Untrusted Data) and CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) vulnerabilities in its Archive_Tar class. When extract is called without a specific prefix path, can trigger unserialization by crafting a tar file with `phar://[path_to_malicious_phar_file]` as path. Object injection can be used to trigger destruct in the loaded PHP classes, all with possible remote code execution that can result in files being deleted or possibly modified.

For Debian 8 Jessie, this problem has been fixed in version 5.6.39+dfsg-0+deb8u2.

We recommend that you upgrade your php5 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);