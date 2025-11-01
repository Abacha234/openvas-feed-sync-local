# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704034");
  script_cve_id("CVE-2017-8807");
  script_tag(name:"creation_date", value:"2017-11-14 23:00:00 +0000 (Tue, 14 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-22 13:27:00 +0000 (Fri, 22 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-4034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4034");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4034");
  script_xref(name:"URL", value:"https://varnish-cache.org/security/VSV00002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'varnish' package(s) announced via the DSA-4034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'shamger' and Carlo Cannas discovered that a programming error in Varnish, a state of the art, high-performance web accelerator, may result in disclosure of memory contents or denial of service.

See [link moved to references] for details.

For the stable distribution (stretch), this problem has been fixed in version 5.0.0-7+deb9u2.

We recommend that you upgrade your varnish packages.");

  script_tag(name:"affected", value:"'varnish' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);