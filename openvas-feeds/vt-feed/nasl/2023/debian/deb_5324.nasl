# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705324");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2873", "CVE-2022-3545", "CVE-2022-3623", "CVE-2022-36280", "CVE-2022-41218", "CVE-2022-45934", "CVE-2022-4696", "CVE-2022-47929", "CVE-2023-0179", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-01-25 02:00:27 +0000 (Wed, 25 Jan 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-5324)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5324");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5324");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5324 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2022-2873

Zheyu Ma discovered that an out-of-bounds memory access flaw in the Intel iSMT SMBus 2.0 host controller driver may result in denial of service (system crash).

CVE-2022-3545

It was discovered that the Netronome Flow Processor (NFP) driver contained a use-after-free flaw in area_cache_get(), which may result in denial of service or the execution of arbitrary code.

CVE-2022-3623

A race condition when looking up a CONT-PTE/PMD size hugetlb page may result in denial of service or an information leak.

CVE-2022-4696

A use-after-free vulnerability was discovered in the io_uring subsystem.

CVE-2022-36280

An out-of-bounds memory write vulnerability was discovered in the vmwgfx driver, which may allow a local unprivileged user to cause a denial of service (system crash).

CVE-2022-41218

Hyunwoo Kim reported a use-after-free flaw in the Media DVB core subsystem caused by refcount races, which may allow a local user to cause a denial of service or escalate privileges.

CVE-2022-45934

An integer overflow in l2cap_config_req() in the Bluetooth subsystem was discovered, which may allow a physically proximate attacker to cause a denial of service (system crash).

CVE-2022-47929

Frederick Lawler reported a NULL pointer dereference in the traffic control subsystem allowing an unprivileged user to cause a denial of service by setting up a specially crafted traffic control configuration.

CVE-2023-0179

Davide Ornaghi discovered incorrect arithmetic when fetching VLAN header bits in the netfilter subsystem, allowing a local user to leak stack and heap addresses or potentially local privilege escalation to root.

CVE-2023-0266

A use-after-free flaw in the sound subsystem due to missing locking may result in denial of service or privilege escalation.

CVE-2023-0394

Kyle Zeng discovered a NULL pointer dereference flaw in rawv6_push_pending_frames() in the network subsystem allowing a local user to cause a denial of service (system crash).

CVE-2023-23454

Kyle Zeng reported that the Class Based Queueing (CBQ) network scheduler was prone to denial of service due to interpreting classification results before checking the classification return code.

CVE-2023-23455

Kyle Zeng reported that the ATM Virtual Circuits (ATM) network scheduler was prone to a denial of service due to interpreting classification results before checking the classification return code.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.162-1.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);