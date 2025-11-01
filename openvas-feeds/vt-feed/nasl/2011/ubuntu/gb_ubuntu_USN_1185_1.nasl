# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840731");
  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");
  script_tag(name:"creation_date", value:"2011-08-27 14:37:49 +0000 (Sat, 27 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1185-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1185-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1185-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1185-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gary Kwong, Igor Bukanov, and Bob Clary discovered multiple memory
vulnerabilities in the Gecko rendering engine. An attacker could use
these to possibly execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2011-2982)

It was discovered that a vulnerability in event management code could
permit JavaScript to be run in the wrong context. This could potentially
allow a malicious website to run code as another website or with escalated
privileges in a chrome-privileged context. (CVE-2011-2981)

It was discovered that an SVG text manipulation routine contained a
dangling pointer vulnerability. An attacker could potentially use this to
crash Thunderbird or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2011-0084)

It was discovered that web content could receive chrome privileges if it
registered for drop events and a browser tab element was dropped into the
content area. This could potentially allow a malicious website to run code
with escalated privileges within Thunderbird. (CVE-2011-2984)

It was discovered that appendChild contained a dangling pointer
vulnerability. An attacker could potentially use this to crash Thunderbird
or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2011-2378)

It was discovered that data from other domains could be read when
RegExp.input was set. This could potentially allow a malicious website
access to private data from other domains. (CVE-2011-2983)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
