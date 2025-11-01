# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840680");
  script_cve_id("CVE-2010-2238", "CVE-2011-1486", "CVE-2011-2178");
  script_tag(name:"creation_date", value:"2011-06-20 06:37:08 +0000 (Mon, 20 Jun 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1152-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1152-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-1152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvirt did not use thread-safe error reporting. A
remote attacker could exploit this to cause a denial of service via
application crash. (CVE-2011-1486)

Eric Blake discovered that libvirt had an off-by-one error which could
be used to reopen disk probing and bypass the fix for CVE-2010-2238. A
privileged attacker in the guest could exploit this to read arbitrary files
on the host. This issue only affected Ubuntu 11.04. By default, guests are
confined by an AppArmor profile which provided partial protection against
this flaw. (CVE-2011-2178)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
