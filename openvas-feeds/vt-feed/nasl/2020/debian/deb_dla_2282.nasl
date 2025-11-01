# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892282");
  script_cve_id("CVE-2020-8163", "CVE-2020-8164", "CVE-2020-8165");
  script_tag(name:"creation_date", value:"2020-07-21 03:01:31 +0000 (Tue, 21 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-17 12:15:00 +0000 (Sat, 17 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2282)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2282");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2282");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/rails");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DLA-2282 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Ruby on Rails, a MVC ruby-based framework geared for web application development, which could lead to remote code execution and untrusted user input usage, depending on the application.

CVE-2020-8163

A code injection vulnerability in Rails would allow an attacker who controlled the `locals` argument of a `render` call to perform a RCE.

CVE-2020-8164

A deserialization of untrusted data vulnerability exists in rails which can allow an attacker to supply information can be inadvertently leaked from Strong Parameters.

CVE-2020-8165

A deserialization of untrusted data vulnernerability exists in rails that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.

For Debian 9 stretch, these problems have been fixed in version 2:4.2.7.1-1+deb9u3.

We recommend that you upgrade your rails packages.

For the detailed security status of rails please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);