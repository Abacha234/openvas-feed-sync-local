# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703631");
  script_cve_id("CVE-2016-5385", "CVE-2016-5399", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");
  script_tag(name:"creation_date", value:"2016-08-02 05:27:45 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3631)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3631");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3631");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3631 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in PHP, a general-purpose scripting language commonly used for web application development.

The vulnerabilities are addressed by upgrading PHP to the new upstream version 5.6.24, which includes additional bug fixes. Please refer to the upstream changelog for more information:


For the stable distribution (jessie), these problems have been fixed in version 5.6.24+dfsg-0+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 7.0.9-1 of the php7.0 source package.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);