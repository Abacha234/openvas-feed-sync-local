# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856842");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-12-13 05:00:33 +0000 (Fri, 13 Dec 2024)");
  script_name("openSUSE: Security Advisory for govulncheck (SUSE-SU-2024:4299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4299-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KNE45TO6CEKG3ASS2LFSWUQ7ETALCEVV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck'
  package(s) announced via the SUSE-SU-2024:4299-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

  * Update to version 0.0.20241209T183251 2024-12-09T18:32:51Z (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3284

  * GO-2024-3286

  * GO-2024-3287

  * GO-2024-3288

  * GO-2024-3289

  * GO-2024-3290

  * GO-2024-3291

  * GO-2024-3292

  * GO-2024-3294

  * GO-2024-3296

  * GO-2024-3299

  * GO-2024-3300

  * GO-2024-3302

  * GO-2024-3303

  * GO-2024-3304

  * GO-2024-3305

  * GO-2024-3307

  * GO-2024-3308

  * GO-2024-3310

  * GO-2024-3311

  * GO-2024-3312

  * GO-2024-3313

  * Update to version 0.0.20241121T195252 2024-11-21T19:52:52Z (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3279

  * GO-2024-3280

  * GO-2024-3281

  * GO-2024-3282

  * GO-2024-3283

  * Update to version 0.0.20241120T172248 2024-11-20T17:22:48Z (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3140

  * GO-2024-3259

  * GO-2024-3265

  * Update to version 0.0.20241119T173509 2024-11-19T17:35:09Z (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2022-0646

  * GO-2024-3267

  * GO-2024-3269

  * GO-2024-3271

  * GO-2024-3272

  * GO-2024-3273

  * GO-2024-3274

  * GO-2024-3275

  * GO-2024-3277

  * GO-2024-3278");

  script_tag(name:"affected", value:"'govulncheck' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
