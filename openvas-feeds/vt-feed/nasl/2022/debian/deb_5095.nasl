# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705095");
  script_cve_id("CVE-2020-36310", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-25636");
  script_tag(name:"creation_date", value:"2022-03-10 02:01:09 +0000 (Thu, 10 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-04 17:35:00 +0000 (Fri, 04 Mar 2022)");

  script_name("Debian: Security Advisory (DSA-5095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5095");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5095");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-36310

A flaw was discovered in the KVM implementation for AMD processors, which could lead to an infinite loop. A malicious VM guest could exploit this to cause a denial of service.

CVE-2022-0001 (INTEL-SA-00598) Researchers at VUSec discovered that the Branch History Buffer in Intel processors can be exploited to create information side channels with speculative execution. This issue is similar to Spectre variant 2, but requires additional mitigations on some processors. This can be exploited to obtain sensitive information from a different security context, such as from user-space to the kernel, or from a KVM guest to the kernel.

CVE-2022-0002 (INTEL-SA-00598) This is a similar issue to CVE-2022-0001, but covers exploitation within a security context, such as from JIT-compiled code in a sandbox to hosting code in the same process. This is partly mitigated by disabling eBPF for unprivileged users with the sysctl: kernel.unprivileged_bpf_disabled=2. This is already the default in Debian 11 bullseye.

CVE-2022-0487

A use-after-free was discovered in the MOXART SD/MMC Host Controller support driver. This flaw does not impact the Debian binary packages as CONFIG_MMC_MOXART is not set.

CVE-2022-0492

Yiqi Sun and Kevin Wang reported that the cgroup-v1 subsystem does not properly restrict access to the release-agent feature. A local user can take advantage of this flaw for privilege escalation and bypass of namespace isolation.

CVE-2022-0617

butt3rflyh4ck discovered a NULL pointer dereference in the UDF filesystem. A local user that can mount a specially crafted UDF image can use this flaw to crash the system.

CVE-2022-25636

Nick Gregory reported a heap out-of-bounds write flaw in the netfilter subsystem. A user with the CAP_NET_ADMIN capability could use this for denial of service or possibly for privilege escalation.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.103-1. This update additionally includes many more bug fixes from stable updates 5.10.93-5.10.103 inclusive.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);