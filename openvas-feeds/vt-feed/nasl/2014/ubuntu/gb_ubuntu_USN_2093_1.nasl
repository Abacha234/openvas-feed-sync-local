# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841696");
  script_cve_id("CVE-2013-6436", "CVE-2013-6457", "CVE-2013-6458", "CVE-2014-0028", "CVE-2014-1447");
  script_tag(name:"creation_date", value:"2014-02-03 08:32:09 +0000 (Mon, 03 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2093-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2093-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-2093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martin Kletzander discovered that libvirt incorrectly handled reading
memory tunables from LXC guests. A local user could possibly use this flaw
to cause libvirtd to crash, resulting in a denial of service. This issue
only affected Ubuntu 13.10. (CVE-2013-6436)

Dario Faggioli discovered that libvirt incorrectly handled the libxl
driver. A local user could possibly use this flaw to cause libvirtd to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 13.10. (CVE-2013-6457)

It was discovered that libvirt contained multiple race conditions in block
device handling. A remote read-only user could use this flaw to cause
libvirtd to crash, resulting in a denial of service. (CVE-2013-6458)

Eric Blake discovered that libvirt incorrectly handled certain ACLs. An
attacker could use this flaw to possibly obtain certain sensitive
information. This issue only affected Ubuntu 13.10. (CVE-2014-0028)

Jiri Denemark discovered that libvirt incorrectly handled keepalives. A
remote attacker could possibly use this flaw to cause libvirtd to crash,
resulting in a denial of service. (CVE-2014-1447)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
