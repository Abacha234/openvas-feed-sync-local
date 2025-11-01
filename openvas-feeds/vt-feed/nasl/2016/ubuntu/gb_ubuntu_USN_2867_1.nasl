# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842599");
  script_cve_id("CVE-2011-4600", "CVE-2014-8136", "CVE-2015-0236", "CVE-2015-5247", "CVE-2015-5313");
  script_tag(name:"creation_date", value:"2016-01-13 05:14:18 +0000 (Wed, 13 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 18:37:00 +0000 (Mon, 18 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2867-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2867-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-2867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvirt incorrectly handled the firewall rules on
bridge networks when the daemon was restarted. This could result in an
unintended firewall configuration. This issue only applied to Ubuntu 12.04
LTS. (CVE-2011-4600)

Peter Krempa discovered that libvirt incorrectly handled locking when
certain ACL checks failed. A local attacker could use this issue to cause
libvirt to stop responding, resulting in a denial of service. This issue
only applied to Ubuntu 14.04 LTS. (CVE-2014-8136)

Luyao Huang discovered that libvirt incorrectly handled VNC passwords in
snapshot and image files. A remote authenticated user could use this issue
to possibly obtain VNC passwords. This issue only affected Ubuntu 14.04
LTS. (CVE-2015-0236)

Han Han discovered that libvirt incorrectly handled volume creation
failure when used with NFS. A remote authenticated user could use this
issue to cause libvirt to crash, resulting in a denial of service. This
issue only applied to Ubuntu 15.10. (CVE-2015-5247)

Ossi Herrala and Joonas Kuorilehto discovered that libvirt incorrectly
performed storage pool name validation. A remote authenticated user could
use this issue to bypass ACLs and gain access to unintended files. This
issue only applied to Ubuntu 14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10.
(CVE-2015-5313)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
