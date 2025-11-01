# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845131");
  script_cve_id("CVE-2021-3655", "CVE-2021-3744", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-41864", "CVE-2021-43056", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-11-12 02:00:44 +0000 (Fri, 12 Nov 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 17:39:00 +0000 (Fri, 25 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5139-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5139-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) announced via the USN-5139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja Van Sprundel discovered that the SCTP implementation in the Linux
kernel did not properly perform size validations on incoming packets in
some situations. An attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2021-3655)

It was discovered that the AMD Cryptographic Coprocessor (CCP) driver in
the Linux kernel did not properly deallocate memory in some error
conditions. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2021-3744, CVE-2021-3764)

It was discovered that the NFC subsystem in the Linux kernel contained a
use-after-free vulnerability in its NFC Controller Interface (NCI)
implementation. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2021-3760)

It was discovered that an integer overflow could be triggered in the eBPF
implementation in the Linux kernel when preallocating objects for stack
maps. A privileged local attacker could use this to cause a denial of
service or possibly execute arbitrary code. (CVE-2021-41864)

It was discovered that the KVM implementation for POWER8 processors in the
Linux kernel did not properly keep track if a wakeup event could be
resolved by a guest. An attacker in a guest VM could possibly use this to
cause a denial of service (host OS crash). (CVE-2021-43056)

It was discovered that the ISDN CAPI implementation in the Linux kernel
contained a race condition in certain situations that could trigger an
array out-of-bounds bug. A privileged local attacker could possibly use
this to cause a denial of service or execute arbitrary code.
(CVE-2021-43389)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
