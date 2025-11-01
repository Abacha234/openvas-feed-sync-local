# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842235");
  script_cve_id("CVE-2015-3209", "CVE-2015-4037", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106");
  script_tag(name:"creation_date", value:"2015-06-11 04:30:50 +0000 (Thu, 11 Jun 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2630-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2630-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2630-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2630-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Tait discovered that QEMU incorrectly handled the virtual PCNET
driver. A malicious guest could use this issue to cause a denial of
service, or possibly execute arbitrary code on the host as the user running
the QEMU process. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2015-3209)

Kurt Seifried discovered that QEMU incorrectly handled certain temporary
files. A local attacker could use this issue to cause a denial of service.
(CVE-2015-4037)

Jan Beulich discovered that the QEMU Xen code incorrectly restricted write
access to the host MSI message data field. A malicious guest could use this
issue to cause a denial of service. This issue only applied to Ubuntu 14.04
LTS, Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-4103)

Jan Beulich discovered that the QEMU Xen code incorrectly restricted access
to the PCI MSI mask bits. A malicious guest could use this issue to cause a
denial of service. This issue only applied to Ubuntu 14.04 LTS, Ubuntu
14.10 and Ubuntu 15.04. (CVE-2015-4104)

Jan Beulich discovered that the QEMU Xen code incorrectly handled MSI-X
error messages. A malicious guest could use this issue to cause a denial of
service. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 14.10 and
Ubuntu 15.04. (CVE-2015-4105)

Jan Beulich discovered that the QEMU Xen code incorrectly restricted write
access to the PCI config space. A malicious guest could use this issue to
cause a denial of service, obtain sensitive information, or possibly
execute arbitrary code. This issue only applied to Ubuntu 14.04 LTS,
Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-4106)");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
