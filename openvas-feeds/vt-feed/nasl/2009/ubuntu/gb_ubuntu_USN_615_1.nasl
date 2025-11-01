# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840324");
  script_cve_id("CVE-2008-1108", "CVE-2008-1109");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-615-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-615-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution' package(s) announced via the USN-615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop of Secunia Research discovered that Evolution did not
properly validate timezone data when processing iCalendar attachments.
If a user disabled the ITip Formatter plugin and viewed a crafted
iCalendar attachment, an attacker could cause a denial of service or
possibly execute code with user privileges. Note that the ITip
Formatter plugin is enabled by default in Ubuntu. (CVE-2008-1108)

Alin Rad Pop of Secunia Research discovered that Evolution did not
properly validate the DESCRIPTION field when processing iCalendar
attachments. If a user were tricked into accepting a crafted
iCalendar attachment and replied to it from the calendar window, an
attacker code cause a denial of service or execute code with user
privileges. (CVE-2008-1109)

Matej Cepl discovered that Evolution did not properly validate date
fields when processing iCalendar attachments. If a user disabled the
ITip Formatter plugin and viewed a crafted iCalendar attachment, an
attacker could cause a denial of service. Note that the ITip
Formatter plugin is enabled by default in Ubuntu.");

  script_tag(name:"affected", value:"'evolution' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
