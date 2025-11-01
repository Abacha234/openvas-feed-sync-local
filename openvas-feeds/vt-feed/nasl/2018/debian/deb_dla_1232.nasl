# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891232");
  script_cve_id("CVE-2017-17558", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-5754");
  script_tag(name:"creation_date", value:"2018-01-08 23:00:00 +0000 (Mon, 08 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:26:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-1232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1232");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1232");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-5754

Multiple researchers have discovered a vulnerability in Intel processors, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Meltdown and is addressed in the Linux kernel for the Intel x86-64 architecture by a patch set named Kernel Page Table Isolation, enforcing a near complete separation of the kernel and userspace address maps and preventing the attack. This solution might have a performance impact, and can be disabled at boot time by passing `pti=off' to the kernel command line.

CVE-2017-17558

Andrey Konovalov reported that USB core did not correctly handle some error conditions during initialisation. A physically present user with a specially designed USB device can use this to cause a denial of service (crash or memory corruption), or possibly for privilege escalation.

CVE-2017-17741

Dmitry Vyukov reported that the KVM implementation for x86 would over-read data from memory when emulating an MMIO write if the kvm_mmio tracepoint was enabled. A guest virtual machine might be able to use this to cause a denial of service (crash).

CVE-2017-17805

It was discovered that some implementations of the Salsa20 block cipher did not correctly handle zero-length input. A local user could use this to cause a denial of service (crash) or possibly have other security impact.

CVE-2017-17806

It was discovered that the HMAC implementation could be used with an underlying hash algorithm that requires a key, which was not intended. A local user could use this to cause a denial of service (crash or memory corruption), or possibly for privilege escalation.

CVE-2017-17807

Eric Biggers discovered that the KEYS subsystem lacked a check for write permission when adding keys to a process's default keyring. A local user could use this to cause a denial of service or to obtain sensitive information.

For Debian 7 Wheezy, these problems have been fixed in version 3.2.96-3.

We recommend that you upgrade your linux packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);