# Antigravity in Gemini Enterprise 로깅 및 IAM 거버넌스 가이드

## 1. 배경 및 제품 개요

Google Antigravity(AGY 2.0 Hub, AGY CLI, IDE Extension)는 Gemini Enterprise(GE) 환경에서 기업용 AI Developer Tools(AI 개발자 도구) 기능으로 통합되었습니다.

엔터프라이즈 환경에서는 데이터 주권, 보안 및 감사 규정(GCP ToS, Data Processor 계약)을 준수해야 하므로, 소비자용 엔드포인트(`aicode.googleapis.com`)가 아닌 기업 전용 백엔드인 **Business AI Code API (`businessaicode.googleapis.com`, BAIC)**를 통해 요청이 처리됩니다.

---

## 2. Cloud Logging 텔레메트리 아키텍처

사용자가 Antigravity 클라이언트에서 프롬프트를 전송하고 코드를 생성하면, BAIC 백엔드의 `TelemetryDispatcher` 파이프라인이 호출 결과를 고객의 Google Cloud 프로젝트 내 Cloud Logging으로 전달합니다.

### 2.1. 로그 스트림 경로
- 로그 이름:
  `projects/{PROJECT_ID}/logs/businessaicode.googleapis.com%2Finference_response`

### 2.2. 로그 페이로드 구조
- `labels.user_id`: 요청을 수행한 사용자 이메일 계정 (예: `user@company.com`)
- `labels.client_name`: 호출한 클라이언트 도구 (`antigravity_hub`, `antigravity_cli` 등)
- `labels.model_id`: 호출에 사용된 Gemini 모델 식별자. 이 라벨이 없는 경우에만 `labels.model`을 fallback으로 사용합니다.
- `jsonPayload.metadata.totalTokenCount`: 해당 요청의 총 토큰 소모량
- `jsonPayload.metadata.promptTokenCount`: 입력 프롬프트 토큰 수
- `jsonPayload.metadata.candidatesTokenCount`: 응답 생성 토큰 수

### 2.3. agy-admin의 메트릭 집계 방식
`agy-admin`의 Logging 클라이언트는 위 로그 스트림을 필터링하여 사용자별(user_id), 집계 주기(daily, weekly, monthly), 윈도우 유형(calendar, rolling)에 맞춰 총 요청 횟수와 토큰 사용량을 계산합니다.

---

## 3. Antigravity in GE의 IAM 권한 체계 및 제어 원리

### 3.1. 필수 IAM 역할 및 API
- 기본 사용자 역할:
  - `roles/discoveryengine.agentspaceUser` (Discovery Engine Agentspace User): 사용자가 Antigravity 및 AI 개발자 도구를 실행하는 데 필요한 기본 IAM 역할
- 필수 활성화 API:
  - `businessaicode.googleapis.com` (Business AI Code API)
  - `discoveryengine.googleapis.com` (Gemini Enterprise / Discovery Engine API)
  - `logging.googleapis.com` (Cloud Logging API)
- 관리자 및 자동화 배치 역할:
  - `roles/discoveryengine.agentspaceAdmin`: 콘솔 설정 제어
  - `roles/resourcemanager.projectIamAdmin`: Cloud Run Job 서비스 계정이 사용자의 IAM 바인딩을 수정하기 위한 필수 권한
  - `roles/logging.viewer`: 추론 메트릭 조회
  - `roles/logging.logWriter`: 관리 감사 로그 기록. v0.1.0 배포 스크립트에는 이 역할이 누락되어 감사 로그 기록이 조용히 실패했습니다.
  - `roles/iam.roleViewer`: 마커 커스텀 역할 정의 조회

### 3.2. Cap 차단 메커니즘
- `revoke` 모드:
  한도 초과 시 사용자의 `roles/discoveryengine.agentspaceUser` 역할을 즉시 회수합니다. 마커 역할을 남기지 않으므로 도구가 자신의 차단 이력을 식별할 수 없고, 자동 복구 대상이 되지 않습니다.
- `custom_role` 모드 (기본 권장값):
  `roles/discoveryengine.agentspaceUser`를 제거하고 마커 커스텀 역할을 부여합니다. 마커 역할은 기본 역할의 권한에서 `businessaicode.*`만 제외한 것으로, Antigravity 개발 도구 호출은 차단하되 일반 Gemini Enterprise 검색·채팅 접근은 유지합니다.

v0.2.0부터 마커 역할은 부여 주체에 따라 두 종류로 분리됩니다.

| 역할 | 부여 주체 | 자동 복구 |
|---|---|---|
| `CustomAntigravityCapBlocked` | 캡 집행 사이클 (`cap apply`, 배치 잡) | 대상 |
| `CustomAntigravityAdminBlocked` | 관리자 수동 `disallow` | 대상 아님 |
| `CustomAntigravityRestrictedUser` | v0.1.0 레거시 | 대상 아님. 관리자 차단으로 취급 |

### 3.3. 자동 복구 (Auto-unblock)
집계 주기가 갱신되어 사용자의 사용량이 캡 이하로 내려가면, 배치 잡은 **`CustomAntigravityCapBlocked` 마커를 보유한 사용자에 한해** 마커를 회수하고 기본 역할을 재부여합니다.

관리자 수동 차단(`CustomAntigravityAdminBlocked`) 및 레거시 역할 보유자는 자동 복구 대상에서 제외됩니다. v0.1.0에서는 두 차단이 동일한 역할을 공유해, 오프보딩 등으로 수동 차단한 사용자가 다음 사이클에 자동으로 재활성화되는 문제가 있었습니다.

또한 사용량 로그 조회가 실패했거나 결과가 0건인 경우(게이트 G3), 자동 복구는 보류됩니다. "로그 0건"과 "사용량 0"은 외부에서 구분되지 않으므로, 관측 장애가 대규모 권한 부여로 이어지는 것을 막기 위한 조치입니다.

### 3.4. 집행 가능성 판정 (6-state 모델)
v0.2.0은 "역할 보유 여부"가 아니라 "이 도구가 해당 사용자의 접근 권한을 제어할 수 있음을 증명할 수 있는가"를 기준으로 사용자를 분류하고, 증명 가능한 경우에만 IAM을 변경합니다.

| 상태 | 자동 차단 | 자동 복구 |
|---|:---:|:---:|
| `ENFORCEABLE_ALLOWED` (개별 `user:` 바인딩에서만 접근 권한 유래) | 가능 | - |
| `CAPPED_BY_TOOL` | - | 가능 |
| `BLOCKED_BY_ADMIN` | - | 불가 |
| `NOT_ENFORCEABLE` | 불가 | 불가 |
| `NO_ACCESS` | 불가 | 불가 |
| `UNKNOWN` | 불가 | 불가 |

`NOT_ENFORCEABLE`로 분류되는 대표적인 경우는 다음과 같습니다.
- `PRIVILEGED_ROLE`: `roles/owner`, `roles/editor` 보유
- `OTHER_ACCESS_ROLE`: `roles/discoveryengine.admin` 등 다른 접근 부여 역할 보유
- `GROUP_GRANT_PRESENT`: 기본 역할이 그룹 또는 도메인 멤버에게 부여되어 있어 사용자 단위 회수가 불가능
- `INHERITED_BINDING`: 상위 폴더·조직에서 상속된 부여
- `CONFLICTING_BINDINGS`: 조건부 바인딩이거나 기본 역할과 마커 역할을 동시에 보유

이들 사용자는 IAM을 변경하지 않고 리포트의 "수동 조치 필요" 목록에 표시됩니다. 이는 v0.1.0에서 그룹 부여 환경의 사용자에 대해 차단 성공으로 보고했으나 실제로는 접근 권한이 유지되던 문제를 해결한 것입니다.

### 3.5. 안전 게이트
집행 사이클은 IAM을 변경하기 전에 다섯 개 게이트를 평가합니다.

| 게이트 | 발동 조건 | 효과 |
|---|---|---|
| `G1_POLICY_READABLE` | 프로젝트 IAM 정책 조회 실패 | 사이클 중단 |
| `G2_ANY_DETERMINATE` | 어떤 사용자의 상태도 판정 불가 | 사이클 중단 |
| `G3_TELEMETRY_HEALTHY` | 사용량 쿼리 실패 또는 0건 | 자동 복구 보류 |
| `G4_CHANGE_BUDGET` | 변경 건수가 `max(10, 인구의 20%)` 초과 | 사이클 중단 |
| `G5_NON_USER_GRANT_ABSENT` | 접근 부여 역할에 그룹/도메인 부여 존재 | 경고 및 해당 사용자 `NOT_ENFORCEABLE` 처리 |

도입 전 `scripts/preflight_check.sh`로 프로젝트의 실제 집행 가능 범위를 먼저 확인하는 것을 권장합니다.

---

## 4. 참고 문서

- [Gemini Enterprise - Configure AI developer tools settings](https://docs.cloud.google.com/gemini/enterprise/docs/ai-developer-tools-settings): AI Developer Tools 설정, 필수 API 및 사전 요구사항 가이드
- [Gemini Enterprise - Create custom roles to restrict access to AI developer tools](https://cloud.google.com/gemini/enterprise/docs/ai-developer-tools-creating-custom-roles): 커스텀 역할 생성 및 권한 제한 가이드
- [Discovery Engine IAM access control](https://cloud.google.com/generative-ai-app-builder/docs/access-control): `roles/discoveryengine.agentspaceUser` 등 역할 정의
- [Cloud Logging Query Language](https://cloud.google.com/logging/docs/view/logging-query-language): 로그 필터링 쿼리 구문
