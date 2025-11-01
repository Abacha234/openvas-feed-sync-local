# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702761");
  script_cve_id("CVE-2013-4761", "CVE-2013-4956");
  script_tag(name:"creation_date", value:"2013-09-18 22:00:00 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2761)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2761");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2761");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'puppet' package(s) announced via the DSA-2761 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in puppet, a centralized configuration management system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-4761

The resource_type service (disabled by default) could be used to make puppet load arbitrary Ruby code from puppet master's file system.

CVE-2013-4956

Modules installed with the Puppet Module Tool might be installed with weak permissions, possibly allowing local users to read or modify them.

The stable distribution (wheezy) has been updated to version 2.7.33 of puppet. This version includes the patches for all the previous DSAs related to puppet in wheezy. In this version, the puppet report format is now correctly reported as version 3.

It is to be expected that future DSAs for puppet update to a newer, bug fix-only, release of the 2.7 branch.

The oldstable distribution (squeeze) has not been updated for this advisory: as of this time there is no fix for CVE-2013-4761 and the package is not affected by CVE-2013-4956.

For the stable distribution (wheezy), these problems have been fixed in version 2.7.23-1~deb7u1.

For the testing distribution (jessie) and the unstable distribution (sid), these problems have been fixed in version 3.2.4-1.

We recommend that you upgrade your puppet packages.");

  script_tag(name:"affected", value:"'puppet' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);