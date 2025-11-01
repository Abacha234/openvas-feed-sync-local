# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843992");
  script_cve_id("CVE-2018-12020", "CVE-2019-6690");
  script_tag(name:"creation_date", value:"2019-05-03 02:00:34 +0000 (Fri, 03 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-06 18:27:00 +0000 (Wed, 06 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3964-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3964-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3964-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-gnupg' package(s) announced via the USN-3964-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcus Brinkmann discovered that GnuPG before 2.2.8 improperly handled certain
command line parameters. A remote attacker could use this to spoof the output of
GnuPG and cause unsigned e-mail to appear signed.
(CVE-2018-12020)

It was discovered that python-gnupg incorrectly handled the GPG passphrase. A
remote attacker could send a specially crafted passphrase that would allow them
to control the output of encryption and decryption operations.
(CVE-2019-6690)");

  script_tag(name:"affected", value:"'python-gnupg' package(s) on Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
