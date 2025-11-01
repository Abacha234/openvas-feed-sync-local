# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840909");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507");
  script_tag(name:"creation_date", value:"2012-03-09 13:27:39 +0000 (Fri, 09 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1373-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1373-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1373-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-1373-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Java HttpServer class did not limit the
number of headers read from a HTTP request. A remote attacker could
cause a denial of service by sending special requests that trigger
hash collisions predictably. (CVE-2011-5035)

ATTENTION: this update changes previous Java HttpServer class behavior
by limiting the number of request headers to 200. This may be increased
by adjusting the sun.net.httpserver.maxReqHeaders property.

It was discovered that the Java Sound component did not properly
check buffer boundaries. A remote attacker could use this to cause
a denial of service or view confidential data. (CVE-2011-3563)

It was discovered that the Java2D implementation does not properly
check graphics rendering objects before passing them to the native
renderer. A remote attacker could use this to cause a denial of
service or to bypass Java sandbox restrictions. (CVE-2012-0497)

It was discovered that an off-by-one error exists in the Java ZIP
file processing code. An attacker could us this to cause a denial of
service through a maliciously crafted ZIP file. (CVE-2012-0501)

It was discovered that the Java AWT KeyboardFocusManager did not
properly enforce keyboard focus security policy. A remote attacker
could use this with an untrusted application or applet to grab keyboard
focus and possibly expose confidential data. (CVE-2012-0502)

It was discovered that the Java TimeZone class did not properly enforce
security policy around setting the default time zone. A remote attacker
could use this with an untrusted application or applet to set a new
default time zone and bypass Java sandbox restrictions. (CVE-2012-0503)

It was discovered the Java ObjectStreamClass did not throw
an accurately identifiable exception when a deserialization
failure occurred. A remote attacker could use this with
an untrusted application or applet to bypass Java sandbox
restrictions. (CVE-2012-0505)

It was discovered that the Java CORBA implementation did not properly
protect repository identifiers on certain CORBA objects. A remote
attacker could use this to corrupt object data. (CVE-2012-0506)

It was discovered that the Java AtomicReferenceArray class
implementation did not properly check if an array was of
the expected Object[] type. A remote attacker could use this
with a malicious application or applet to bypass Java sandbox
restrictions. (CVE-2012-0507)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
