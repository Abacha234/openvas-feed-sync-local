# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704112");
  script_cve_id("CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566");
  script_tag(name:"creation_date", value:"2018-02-13 23:00:00 +0000 (Tue, 13 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4112");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4112");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-254.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2017-17563

Jan Beulich discovered that an incorrect reference count overflow check in x86 shadow mode may result in denial of service or privilege escalation.

CVE-2017-17564

Jan Beulich discovered that improper x86 shadow mode reference count error handling may result in denial of service or privilege escalation.

CVE-2017-17565

Jan Beulich discovered that an incomplete bug check in x86 log-dirty handling may result in denial of service.

CVE-2017-17566

Jan Beulich discovered that x86 PV guests may gain access to internally used pages which could result in denial of service or potential privilege escalation.

In addition this update ships the Comet shim to address the Meltdown class of vulnerabilities for guests with legacy PV kernels. In addition, the package provides the Xen PTI stage 1 mitigation which is built-in and enabled by default on Intel systems, but can be disabled with `xpti=false' on the hypervisor command line (It does not make sense to use both xpti and the Comet shim.)

Please refer to the following URL for more details on how to configure individual mitigation strategies: [link moved to references]

Additional information can also be found in README.pti and README.comet.

For the stable distribution (stretch), these problems have been fixed in version 4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);