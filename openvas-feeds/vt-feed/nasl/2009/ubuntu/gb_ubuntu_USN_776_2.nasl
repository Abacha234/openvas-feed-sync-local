# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64175");
  script_cve_id("CVE-2008-1945", "CVE-2008-2004", "CVE-2008-2382", "CVE-2008-4539", "CVE-2008-5714");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-776-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-776-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-776-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/375937");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the USN-776-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-776-1 fixed vulnerabilities in KVM. Due to an incorrect fix, a
regression was introduced in Ubuntu 8.04 LTS that caused KVM to fail to
boot virtual machines started via libvirt. This update fixes the problem.
We apologize for the inconvenience.

Original advisory details:

 Avi Kivity discovered that KVM did not correctly handle certain disk
 formats. A local attacker could attach a malicious partition that would
 allow the guest VM to read files on the VM host. (CVE-2008-1945,
 CVE-2008-2004)

 Alfredo Ortega discovered that KVM's VNC protocol handler did not
 correctly validate certain messages. A remote attacker could send
 specially crafted VNC messages that would cause KVM to consume CPU
 resources, leading to a denial of service. (CVE-2008-2382)

 Jan Niehusmann discovered that KVM's Cirrus VGA implementation over VNC
 did not correctly handle certain bitblt operations. A local attacker could
 exploit this flaw to potentially execute arbitrary code on the VM host or
 crash KVM, leading to a denial of service. (CVE-2008-4539)

 It was discovered that KVM's VNC password checks did not use the correct
 length. A remote attacker could exploit this flaw to cause KVM to crash,
 leading to a denial of service. (CVE-2008-5714)");

  script_tag(name:"affected", value:"'kvm' package(s) on Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
