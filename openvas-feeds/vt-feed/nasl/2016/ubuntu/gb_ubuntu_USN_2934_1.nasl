# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842723");
  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1964", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"creation_date", value:"2016-05-06 09:59:31 +0000 (Fri, 06 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-2934-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2934-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2934-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bob Clary, Christoph Diehl, Christian Holler, Andrew McCreight, Daniel
Holbert, Jesse Ruderman, and Randell Jesup discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2016-1952)

Nicolas Golubovic discovered that CSP violation reports can be used to
overwrite local files. If a user were tricked in to opening a specially
crafted website in a browsing context with addon signing disabled and
unpacked addons installed, an attacker could potentially exploit this to
gain additional privileges. (CVE-2016-1954)

Jose Martinez and Romina Santillan discovered a memory leak in
libstagefright during MPEG4 video file processing in some circumstances.
If a user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause a
denial of service via memory exhaustion. (CVE-2016-1957)

A use-after-free was discovered in the HTML5 string parser. If a user were
tricked in to opening a specially crafted website in a browsing context, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2016-1960)

A use-after-free was discovered in the SetBody function of HTMLDocument.
If a user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2016-1961)

Nicolas Gregoire discovered a use-after-free during XML transformations.
If a user were tricked in to opening a specially crafted website in a
browsing context, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2016-1964)

A memory corruption issues was discovered in the NPAPI subsystem. If
a user were tricked in to opening a specially crafted website in a
browsing context with a malicious plugin installed, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2016-1966)

Ronald Crane discovered an out-of-bounds read following a failed
allocation in the HTML parser in some circumstances. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Thunderbird. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
