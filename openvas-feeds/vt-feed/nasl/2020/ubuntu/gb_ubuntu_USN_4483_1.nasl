# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844565");
  script_cve_id("CVE-2019-20810", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10781", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12771", "CVE-2020-13974", "CVE-2020-14356", "CVE-2020-15393", "CVE-2020-24394");
  script_tag(name:"creation_date", value:"2020-09-03 03:00:36 +0000 (Thu, 03 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4483-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4483-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4483-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-4483-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chuhong Yuan discovered that go7007 USB audio device driver in the Linux
kernel did not properly deallocate memory in some failure conditions. A
physically proximate attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2019-20810)

Fan Yang discovered that the mremap implementation in the Linux kernel did
not properly handle DAX Huge Pages. A local attacker with access to DAX
storage could use this to gain administrative privileges. (CVE-2020-10757)

It was discovered that the Linux kernel did not correctly apply Speculative
Store Bypass Disable (SSBD) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10766)

It was discovered that the Linux kernel did not correctly apply Indirect
Branch Predictor Barrier (IBPB) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10767)

It was discovered that the Linux kernel could incorrectly enable Indirect
Branch Speculation after it has been disabled for a process via a prctl()
call. A local attacker could possibly use this to expose sensitive
information. (CVE-2020-10768)

Luca Bruno discovered that the zram module in the Linux kernel did not
properly restrict unprivileged users from accessing the hot_add sysfs file.
A local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2020-10781)

It was discovered that the XFS file system implementation in the Linux
kernel did not properly validate meta data in some circumstances. An
attacker could use this to construct a malicious XFS image that, when
mounted, could cause a denial of service. (CVE-2020-12655)

It was discovered that the bcache subsystem in the Linux kernel did not
properly release a lock in some error conditions. A local attacker could
possibly use this to cause a denial of service. (CVE-2020-12771)

It was discovered that the Virtual Terminal keyboard driver in the Linux
kernel contained an integer overflow. A local attacker could possibly use
this to have an unspecified impact. (CVE-2020-13974)

It was discovered that the cgroup v2 subsystem in the Linux kernel did not
properly perform reference counting in some situations, leading to a NULL
pointer dereference. A local attacker could use this to cause a denial of
service or possibly gain administrative privileges. (CVE-2020-14356)

Kyungtae Kim discovered that the USB testing driver in the Linux kernel did
not properly deallocate memory on disconnect events. A physically proximate
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2020-15393)

It was discovered that the NFS server implementation in the Linux kernel
did not properly honor umask settings when setting permissions while
creating file system objects if the underlying file system did not support
ACLs. An attacker could possibly use this to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
