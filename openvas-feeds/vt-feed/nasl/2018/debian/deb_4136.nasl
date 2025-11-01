# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704136");
  script_cve_id("CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122");
  script_tag(name:"creation_date", value:"2018-03-13 23:00:00 +0000 (Tue, 13 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-18 22:15:00 +0000 (Tue, 18 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-4136)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4136");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4136");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/curl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-4136 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in cURL, an URL transfer library.

CVE-2018-1000120

Duy Phan Thanh discovered that curl could be fooled into writing a zero byte out of bounds when curl is told to work on an FTP URL with the setting to only issue a single CWD command, if the directory part of the URL contains a '%00' sequence.

CVE-2018-1000121

Dario Weisser discovered that curl might dereference a near-NULL address when getting an LDAP URL due to the ldap_get_attribute_ber() function returning LDAP_SUCCESS and a NULL pointer. A malicious server might cause libcurl-using applications that allow LDAP URLs, or that allow redirects to LDAP URLs to crash.

CVE-2018-1000122

OSS-fuzz, assisted by Max Dymond, discovered that curl could be tricked into copying data beyond the end of its heap based buffer when asked to transfer an RTSP URL.

For the oldstable distribution (jessie), these problems have been fixed in version 7.38.0-4+deb8u10.

For the stable distribution (stretch), these problems have been fixed in version 7.52.1-5+deb9u5.

We recommend that you upgrade your curl packages.

For the detailed security status of curl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);