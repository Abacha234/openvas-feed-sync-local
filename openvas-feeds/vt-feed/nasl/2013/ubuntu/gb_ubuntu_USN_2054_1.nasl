# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841654");
  script_cve_id("CVE-2012-6150", "CVE-2013-4408", "CVE-2013-4475");
  script_tag(name:"creation_date", value:"2013-12-17 06:38:41 +0000 (Tue, 17 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2054-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2054-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-2054-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Winbind incorrectly handled invalid group names with
the require_membership_of parameter. If an administrator used an invalid
group name by mistake, access was granted instead of having the login fail.
(CVE-2012-6150)

Stefan Metzmacher and Michael Adam discovered that Samba incorrectly
handled DCE-RPC fragment length fields. A remote attacker could use this
issue to cause Samba to crash, resulting in a denial of service, or
possibly execute arbitrary code as the root user. (CVE-2013-4408)

Hemanth Thummala discovered that Samba incorrectly handled file
permissions when vfs_streams_depot or vfs_streams_xattr were enabled. A
remote attacker could use this issue to bypass intended restrictions.
(CVE-2013-4475)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
