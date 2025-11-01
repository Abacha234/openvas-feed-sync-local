# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843285");
  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7780", "CVE-2017-7781", "CVE-2017-7783", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7788", "CVE-2017-7789", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7794", "CVE-2017-7797", "CVE-2017-7798", "CVE-2017-7799", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7806", "CVE-2017-7807", "CVE-2017-7808", "CVE-2017-7809");
  script_tag(name:"creation_date", value:"2017-08-17 05:51:28 +0000 (Thu, 17 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3391-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3391-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3391-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1711137");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox' package(s) announced via the USN-3391-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3391-1 fixed vulnerabilities in Firefox. This update provides the
corresponding update for Ubufox.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to conduct cross-site scripting (XSS) attacks,
 bypass sandbox restrictions, obtain sensitive information, spoof the
 origin of modal alerts, bypass same origin restrictions, read
 uninitialized memory, cause a denial of service via program crash or hang,
 or execute arbitrary code. (CVE-2017-7753, CVE-2017-7779, CVE-2017-7780,
 CVE-2017-7781, CVE-2017-7783, CVE-2017-7784, CVE-2017-7785, CVE-2017-7786,
 CVE-2017-7787, CVE-2017-7788, CVE-2017-7789, CVE-2017-7791, CVE-2017-7792,
 CVE-2017-7794, CVE-2017-7797, CVE-2017-7798, CVE-2017-7799, CVE-2017-7800,
 CVE-2017-7801, CVE-2017-7802, CVE-2017-7803, CVE-2017-7806, CVE-2017-7807,
 CVE-2017-7808, CVE-2017-7809)");

  script_tag(name:"affected", value:"'ubufox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
