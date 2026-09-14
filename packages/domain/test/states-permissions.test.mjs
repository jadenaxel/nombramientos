import test from "node:test";
import assert from "node:assert/strict";

import {
  DomainError,
  ASSIGNMENT_STATES,
  PERMISSIONS,
  assertAssignmentTransition,
  assertCandidacyTransition,
  assertDemoReferenceFixture,
  assertEligibleForFormalReport,
  assertOfficeProcessTransition,
  assertRoundTransition,
  assertTenantRoleGrantAllowed,
  assignmentStateAfterCongregationalDecision,
  canTransitionOfficeProcess,
  permissionsForRole
} from "../dist/index.js";

function hasDomainCode(code) {
  return (error) => error instanceof DomainError && error.code === code;
}

test("la ruta feliz del proceso conserva todas las fases institucionales", () => {
  const states = [
    "PENDIENTE",
    "CONFIGURADO",
    "PROPUESTAS_ABIERTAS",
    "PROPUESTAS_CERRADAS",
    "DEPURACION",
    "LISTA_CONFIRMADA",
    "VOTACION_ABIERTA",
    "VOTACION_CERRADA",
    "ESCRUTINIO",
    "RESULTADO_INTERNO",
    "RECOMENDACION_CONFIRMADA",
    "CERRADO"
  ];

  for (let index = 0; index < states.length - 1; index += 1) {
    assert.doesNotThrow(() =>
      assertOfficeProcessTransition(states[index], states[index + 1])
    );
  }
});

test("el cliente no puede saltar de propuestas abiertas a votación", () => {
  assert.throws(
    () =>
      assertOfficeProcessTransition(
        "PROPUESTAS_ABIERTAS",
        "VOTACION_ABIERTA"
      ),
    hasDomainCode("INVALID_STATE_TRANSITION")
  );
});

test("una pausa solo reanuda la fase de la que provino", () => {
  assert.equal(
    canTransitionOfficeProcess("VOTACION_ABIERTA", "PAUSADO"),
    true
  );
  assert.equal(
    canTransitionOfficeProcess("PAUSADO", "VOTACION_ABIERTA", {
      pausedFrom: "VOTACION_ABIERTA"
    }),
    true
  );
  assert.equal(
    canTransitionOfficeProcess("PAUSADO", "ESCRUTINIO", {
      pausedFrom: "VOTACION_ABIERTA"
    }),
    false
  );
});

test("una ronda publicada y un proceso anulado son terminales", () => {
  assert.throws(
    () => assertRoundTransition("PUBLISHED", "COUNTING"),
    hasDomainCode("INVALID_STATE_TRANSITION")
  );
  assert.equal(canTransitionOfficeProcess("ANULADO", "CONFIGURADO"), false);
});

test("una recomendación no puede saltar directamente a elección congregacional", () => {
  assert.throws(
    () =>
      assertAssignmentTransition(
        "ACEPTACION_PENDIENTE",
        "ELEGIDA_POR_IGLESIA"
      ),
    hasDomainCode("INVALID_STATE_TRANSITION")
  );

  const path = [
    "PROPUESTA_INTERNA",
    "ACEPTACION_PENDIENTE",
    "ACEPTADA",
    "PRESENTADA_A_IGLESIA",
    "ELEGIDA_POR_IGLESIA",
    "VIGENTE",
    "FINALIZADA"
  ];
  for (let index = 0; index < path.length - 1; index += 1) {
    assert.doesNotThrow(() =>
      assertAssignmentTransition(path[index], path[index + 1])
    );
  }
});

test("la matriz completa de asignaciones permite solo las transiciones institucionales explícitas", () => {
  const allowed = new Set([
    "PROPUESTA_INTERNA>ACEPTACION_PENDIENTE",
    "PROPUESTA_INTERNA>RETIRADA",
    "ACEPTACION_PENDIENTE>ACEPTADA",
    "ACEPTACION_PENDIENTE>DECLINADA",
    "ACEPTACION_PENDIENTE>RETIRADA",
    "ACEPTADA>PRESENTADA_A_IGLESIA",
    "ACEPTADA>DECLINADA",
    "ACEPTADA>RETIRADA",
    "PRESENTADA_A_IGLESIA>ELEGIDA_POR_IGLESIA",
    "PRESENTADA_A_IGLESIA>DEVUELTA_A_COMISION",
    "PRESENTADA_A_IGLESIA>RETIRADA",
    "ELEGIDA_POR_IGLESIA>VIGENTE",
    "ELEGIDA_POR_IGLESIA>SUSTITUIDA",
    "VIGENTE>FINALIZADA",
    "VIGENTE>SUSTITUIDA",
  ]);
  for (const from of ASSIGNMENT_STATES) {
    for (const to of ASSIGNMENT_STATES) {
      const transition = `${from}>${to}`;
      if (allowed.has(transition)) {
        assert.doesNotThrow(() => assertAssignmentTransition(from, to), transition);
      } else {
        assert.throws(() => assertAssignmentTransition(from, to), hasDomainCode("INVALID_STATE_TRANSITION"), transition);
      }
    }
  }
});

test("solo candidaturas revisadas pueden confirmarse para la boleta", () => {
  assert.throws(
    () => assertCandidacyTransition("PROPOSED", "CONFIRMED_FOR_BALLOT"),
    hasDomainCode("INVALID_STATE_TRANSITION")
  );
  assert.doesNotThrow(() =>
    assertCandidacyTransition("PROPOSED", "UNDER_REVIEW")
  );
  assert.doesNotThrow(() =>
    assertCandidacyTransition("UNDER_REVIEW", "CONFIRMED_FOR_BALLOT")
  );
});

test("el informe exige aceptación y la decisión congregacional exige presentación", () => {
  assert.throws(
    () => assertEligibleForFormalReport("PENDING"),
    hasDomainCode("CONSENT_REQUIRED")
  );
  assert.doesNotThrow(() => assertEligibleForFormalReport("ACCEPTED"));
  assert.equal(
    assignmentStateAfterCongregationalDecision(
      "PRESENTADA_A_IGLESIA",
      "ELECTED"
    ),
    "ELEGIDA_POR_IGLESIA"
  );
  assert.equal(
    assignmentStateAfterCongregationalDecision(
      "PRESENTADA_A_IGLESIA",
      "RETURNED_TO_COMMITTEE"
    ),
    "DEVUELTA_A_COMISION"
  );
  assert.throws(
    () =>
      assignmentStateAfterCongregationalDecision(
        "RESULTADO_INTERNO",
        "ELECTED"
      ),
    hasDomainCode("INVALID_CONGREGATIONAL_DECISION")
  );
});

test("el administrador global no recibe contenido ni derecho de voto", () => {
  const permissions = permissionsForRole("GLOBAL_ADMIN");
  assert.equal(permissions.has(PERMISSIONS.PLATFORM_TENANT_PROVISION), true);
  assert.equal(permissions.has(PERMISSIONS.MEMBER_READ), false);
  assert.equal(permissions.has(PERMISSIONS.BALLOT_SUBMIT), false);
  assert.equal(permissions.has(PERMISSIONS.TALLY_CUSTODY), false);
});

test("el rol de junta permite enviar, mientras administrar no confiere voto", () => {
  const member = permissionsForRole("COMMITTEE_MEMBER");
  const churchAdmin = permissionsForRole("CHURCH_ADMIN");
  assert.equal(member.has(PERMISSIONS.PROPOSAL_SUBMIT), true);
  assert.equal(member.has(PERMISSIONS.BALLOT_SUBMIT), true);
  assert.equal(churchAdmin.has(PERMISSIONS.BALLOT_SUBMIT), false);
});

test("la formación y ordenación usan permisos independientes de elegibilidad y elección", () => {
  const admin = permissionsForRole("CHURCH_ADMIN");
  const chair = permissionsForRole("COMMITTEE_CHAIR");
  const member = permissionsForRole("COMMITTEE_MEMBER");
  assert.equal(admin.has(PERMISSIONS.MEMBER_QUALIFICATION_READ), true);
  assert.equal(admin.has(PERMISSIONS.MEMBER_QUALIFICATION_MANAGE), true);
  assert.equal(chair.has(PERMISSIONS.MEMBER_QUALIFICATION_READ), true);
  assert.equal(chair.has(PERMISSIONS.MEMBER_QUALIFICATION_MANAGE), false);
  assert.equal(member.has(PERMISSIONS.MEMBER_QUALIFICATION_READ), false);
  assert.notEqual(PERMISSIONS.MEMBER_QUALIFICATION_MANAGE, PERMISSIONS.MEMBER_ELIGIBILITY_MANAGE);
});

test("un rol local no concede permisos globales ni más de lo delegable", () => {
  const actorDelegable = new Set([
    PERMISSIONS.MEMBER_READ,
    PERMISSIONS.REPORT_READ
  ]);
  assert.deepEqual(
    assertTenantRoleGrantAllowed(
      [PERMISSIONS.REPORT_READ, PERMISSIONS.MEMBER_READ],
      actorDelegable
    ),
    [PERMISSIONS.MEMBER_READ, PERMISSIONS.REPORT_READ]
  );
  assert.throws(
    () =>
      assertTenantRoleGrantAllowed(
        [PERMISSIONS.PLATFORM_TENANT_SUSPEND],
        new Set([PERMISSIONS.PLATFORM_TENANT_SUSPEND])
      ),
    hasDomainCode("PERMISSION_ESCALATION")
  );
  assert.throws(
    () =>
      assertTenantRoleGrantAllowed(
        [PERMISSIONS.PRIVATE_NOTE_READ],
        actorDelegable
      ),
    hasDomainCode("PERMISSION_ESCALATION")
  );
});

test("el fixture expone una autoverificación reutilizable", () => {
  assert.doesNotThrow(() => assertDemoReferenceFixture());
});
