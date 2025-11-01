# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842153");
  script_cve_id("CVE-2014-3591", "CVE-2014-5270", "CVE-2015-0837", "CVE-2015-1606", "CVE-2015-1607");
  script_tag(name:"creation_date", value:"2015-04-02 05:13:20 +0000 (Thu, 02 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-14 13:59:00 +0000 (Sat, 14 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-2554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2554-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2554-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg, gnupg2' package(s) announced via the USN-2554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Genkin, Lev Pachmanov, Itamar Pipman, and Eran Tromer discovered
that GnuPG was susceptible to an attack via physical side channels. A local
attacker could use this attack to possibly recover private keys.
(CVE-2014-3591)

Daniel Genkin, Adi Shamir, and Eran Tromer discovered that GnuPG was
susceptible to an attack via physical side channels. A local attacker could
use this attack to possibly recover private keys. (CVE-2015-0837)

Hanno Bock discovered that GnuPG incorrectly handled certain malformed
keyrings. If a user or automated system were tricked into opening a
malformed keyring, a remote attacker could use this issue to cause GnuPG to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2015-1606, CVE-2015-1607)

In addition, this update improves GnuPG security by validating that the
keys returned by keyservers match those requested.");

  script_tag(name:"affected", value:"'gnupg, gnupg2' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
