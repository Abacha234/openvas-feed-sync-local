# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845290");
  script_cve_id("CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-39685", "CVE-2021-39698", "CVE-2021-4135", "CVE-2021-4197", "CVE-2021-43975", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45402", "CVE-2021-45480", "CVE-2022-0264", "CVE-2022-0382", "CVE-2022-0435", "CVE-2022-0492", "CVE-2022-0516", "CVE-2022-0742", "CVE-2022-23222");
  script_tag(name:"creation_date", value:"2022-03-23 02:00:56 +0000 (Wed, 23 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5337-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5337-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-5337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the BPF verifier in the Linux kernel did not
properly restrict pointer types in certain situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-23222)

Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the
Linux kernel did not properly restrict access to the cgroups v1
release_agent feature. A local attacker could use this to gain
administrative privileges. (CVE-2022-0492)

Jurgen Gross discovered that the Xen subsystem within the Linux kernel did
not adequately limit the number of events driver domains (unprivileged PV
backends) could send to other guest VMs. An attacker in a driver domain
could use this to cause a denial of service in other guest VMs.
(CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

Jurgen Gross discovered that the Xen network backend driver in the Linux
kernel did not adequately limit the amount of queued packets when a guest
did not process them. An attacker in a guest VM can use this to cause a
denial of service (excessive kernel memory consumption) in the network
backend domain. (CVE-2021-28714, CVE-2021-28715)

Szymon Heidrich discovered that the USB Gadget subsystem in the Linux
kernel did not properly restrict the size of control requests for certain
gadget types, leading to possible out of bounds reads or writes. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-39685)

It was discovered that a race condition existed in the poll implementation
in the Linux kernel, resulting in a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-39698)

It was discovered that the simulated networking device driver for the Linux
kernel did not properly initialize memory in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-4135)

Eric Biederman discovered that the cgroup process migration implementation
in the Linux kernel did not perform permission checks correctly in some
situations. A local attacker could possibly use this to gain administrative
privileges. (CVE-2021-4197)

Brendan Dolan-Gavitt discovered that the aQuantia AQtion Ethernet device
driver in the Linux kernel did not properly validate meta-data coming from
the device. A local attacker who can control an emulated device can use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-43975)

It was discovered that the ARM Trusted Execution Environment (TEE)
subsystem in the Linux kernel contained a race condition leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service or possibly execute arbitrary code. (CVE-2021-44733)

It was discovered that the Phone Network ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
