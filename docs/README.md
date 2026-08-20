# AI Travel Planner Documentation

The documents in this directory describe the product vision, business rules, software requirements, API contracts, and architectural design of the backend service.

| Document                    | Purpose                                                                 | Primary Audience                 |
| --------------------------- | ----------------------------------------------------------------------- | -------------------------------- |
| [PRD](./PRD.md)             | Product problem, scope, personas, business rules, KPIs, and roadmap     | Product Owner, BA, Developer, QA |
| [SRS](./SRS.md)             | Functional/non-functional requirements, data schemas, security, tests   | Developer, QA, DevOps            |
| [API](./API.md)             | Endpoints, request/response formats, and API invocation guidelines      | Frontend, Mobile, Integration    |
| [Structure](./STRUCTURE.md) | Source code structure, modular architecture, and file conventions       | Developer, Reviewer              |

## Recommended Reading Order

1. Read the **PRD** to understand users, problem statements, and business rules.
2. Read the **SRS** for technical requirements, data models, and edge cases.
3. Refer to **API Documentation** when integrating frontend applications or manual testing.
4. Consult **Structure** when extending codebase or performing code reviews.

## Maintenance Rules

- Any business logic change must update the PRD and related rule codes.
- Any change to endpoints, validation, status codes, schemas, or permissions must update SRS and API docs.
- Any change to modules, folders, or dependencies must update the Structure document.
- All documents must clearly distinguish currently implemented features from the future roadmap.
