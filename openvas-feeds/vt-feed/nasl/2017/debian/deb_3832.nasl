# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703832");
  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396", "CVE-2017-5398", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410");
  script_tag(name:"creation_date", value:"2017-04-19 22:00:00 +0000 (Wed, 19 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 13:20:00 +0000 (Tue, 07 Aug 2018)");

  script_name("Debian: Security Advisory (DSA-3832)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3832");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3832");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-3832 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Thunderbird, which may may lead to the execution of arbitrary code or information leaks.

With this update, the Icedove packages are de-branded back to the official Mozilla branding. With the removing of the Debian branding the packages are also renamed back to the official names used by Mozilla.

The Thunderbird package is using a different default profile folder, the default profile folder is now '$(HOME)/.thunderbird'. The users profile folder, that was used in Icedove, will get migrated to the new profile folder on the first start, that can take a little bit more time.

Please read README.Debian for getting more information about the changes.

For the stable distribution (jessie), these problems have been fixed in version 1:45.8.0-3~deb8u1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);