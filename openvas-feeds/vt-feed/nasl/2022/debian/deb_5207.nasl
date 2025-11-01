# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705207");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2585", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-36879", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-17 01:00:13 +0000 (Wed, 17 Aug 2022)");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 13:41:00 +0000 (Thu, 04 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5207)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5207");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5207");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5207 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2022-2585

A use-after-free flaw in the implementation of POSIX CPU timers may result in denial of service or in local privilege escalation.

CVE-2022-2586

A use-after-free in the Netfilter subsystem may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

CVE-2022-2588

Zhenpeng Lin discovered a use-after-free flaw in the cls_route filter implementation which may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

CVE-2022-26373

It was discovered that on certain processors with Intel's Enhanced Indirect Branch Restricted Speculation (eIBRS) capabilities there are exceptions to the documented properties in some situations, which may result in information disclosure.

Intel's explanation of the issue can be found at

CVE-2022-29900

Johannes Wikner and Kaveh Razavi reported that for AMD/Hygon processors, mis-trained branch predictions for return instructions may allow arbitrary speculative code execution under certain microarchitecture-dependent conditions.

A list of affected AMD CPU types can be found at

CVE-2022-29901

Johannes Wikner and Kaveh Razavi reported that for Intel processors (Intel Core generation 6, 7 and 8), protections against speculative branch target injection attacks were insufficient in some circumstances, which may allow arbitrary speculative code execution under certain microarchitecture-dependent conditions.

More information can be found at

CVE-2022-36879

A flaw was discovered in xfrm_expand_policies in the xfrm subsystem which can cause a reference count to be dropped twice.

CVE-2022-36946

Domingo Dirutigliano and Nicola Guerrera reported a memory corruption flaw in the Netfilter subsystem which may result in denial of service.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.136-1.

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