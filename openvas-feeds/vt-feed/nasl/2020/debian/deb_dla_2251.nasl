# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892251");
  script_cve_id("CVE-2020-8164", "CVE-2020-8165");
  script_tag(name:"creation_date", value:"2020-06-20 03:00:10 +0000 (Sat, 20 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-17 12:15:00 +0000 (Sat, 17 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2251");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2251");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DLA-2251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in Ruby on Rails, a MVC ruby-based framework geared for web application development, which could lead to remote code execution and untrusted user input usage, depending on the application.

CVE-2020-8164

Strong parameters bypass vector in ActionPack. In some cases user supplied information can be inadvertently leaked from Strong Parameters. Specifically the return value of `each`, or `each_value`, or `each_pair` will return the underlying untrusted hash of data that was read from the parameters. Applications that use this return value may be inadvertently use untrusted user input.

CVE-2020-8165

Potentially unintended unmarshalling of user-provided objects in MemCacheStore. There is potentially unexpected behaviour in the MemCacheStore where, when untrusted user input is written to the cache store using the `raw: true` parameter, re-reading the result from the cache can evaluate the user input as a Marshalled object instead of plain text. Unmarshalling of untrusted user input can have impact up to and including RCE. At a minimum, this vulnerability allows an attacker to inject untrusted Ruby objects into a web application.

In addition to upgrading to the latest versions of Rails, developers should ensure that whenever they are calling `Rails.cache.fetch` they are using consistent values of the `raw` parameter for both reading and writing.

For Debian 8 Jessie, these problems have been fixed in version 2:4.1.8-1+deb8u7.

We recommend that you upgrade your rails packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);