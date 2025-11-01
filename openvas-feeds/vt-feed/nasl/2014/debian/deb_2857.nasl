# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702857");
  script_cve_id("CVE-2013-6429", "CVE-2013-6430");
  script_tag(name:"creation_date", value:"2014-02-07 23:00:00 +0000 (Fri, 07 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-22 16:15:00 +0000 (Wed, 22 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-2857)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2857");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2857");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libspring-java' package(s) announced via the DSA-2857 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered by the Spring development team that the fix for the XML External Entity (XXE) Injection ( CVE-2013-4152) in the Spring Framework was incomplete.

Spring MVC's SourceHttpMessageConverter also processed user provided XML and neither disabled XML external entities nor provided an option to disable them. SourceHttpMessageConverter has been modified to provide an option to control the processing of XML external entities and that processing is now disabled by default.

In addition Jon Passki discovered a possible XSS vulnerability: The JavaScriptUtils.javaScriptEscape() method did not escape all characters that are sensitive within either a JS single quoted string, JS double quoted string, or HTML script data context. In most cases this will result in an unexploitable parse error but in some cases it could result in an XSS vulnerability.

For the stable distribution (wheezy), these problems have been fixed in version 3.0.6.RELEASE-6+deb7u2.

For the testing distribution (jessie), these problems have been fixed in version 3.0.6.RELEASE-11.

For the unstable distribution (sid), these problems have been fixed in version 3.0.6.RELEASE-11.

We recommend that you upgrade your libspring-java packages.");

  script_tag(name:"affected", value:"'libspring-java' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);