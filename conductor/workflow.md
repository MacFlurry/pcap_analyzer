# Project Workflow

## Guiding Principles

1. **The Plan is the Source of Truth:** All work must be tracked in `plan.md`
2. **The Tech Stack is Deliberate:** Changes to the tech stack must be documented in `tech-stack.md` *before* implementation
3. **Test-Driven Development:** Write unit tests before implementing functionality
4. **High Code Coverage:** Target 60%+ global coverage, 70%+ for security-critical modules (auth, file validation, input sanitization)
5. **User Experience First:** Every decision should prioritize user experience
6. **Non-Interactive & CI-Aware:** Prefer non-interactive commands. Use `CI=true` for watch-mode tools (tests, linters) to ensure single execution.

## Task Workflow

All tasks follow a strict lifecycle:

### Standard Task Workflow

1. **Select Task:** Choose the next available task from `plan.md` in sequential order

2. **Mark In Progress:** Before beginning work, edit `plan.md` and change the task from `[ ]` to `[~]`

3. **Write Failing Tests (Red Phase):**
   - Create a new test file for the feature or bug fix.
   - Write one or more unit tests that clearly define the expected behavior and acceptance criteria for the task.
   - **RECOMMENDED:** Run tests to confirm they fail as expected (Red phase of TDD).

4. **Implement to Pass Tests (Green Phase):**
   - Write application code to make tests pass.
   - Run the test suite again and confirm that all tests now pass. This is the "Green" phase.

5. **Refactor (Optional but Recommended):**
   - Refactor code to improve clarity and remove duplication while maintaining passing tests.
   - Rerun tests to ensure they still pass after refactoring.

6. **Verify Coverage:** Run coverage reports using the project's chosen tools. For the PCAP Analyzer (Python), this looks like:
   ```bash
   pytest --cov=app --cov=src --cov-report=term-missing
   ```
   Target: >60% coverage for new code (70%+ for security-critical modules).

7. **Document Deviations:** If implementation differs from tech stack:
   - **STOP** implementation
   - Update `tech-stack.md` with new design
   - Add dated note explaining the change
   - Resume implementation

8. **Commit Code Changes:**
   - Stage all code changes related to the task.
   - Propose a clear, concise commit message following the project's structured format (e.g., `FEATURE v5.x.x: <Description>`).
   - The commit message MUST include a detailed summary of the task, including changes, modified files, and the "why" behind the implementation.
   - Perform the commit.

9. **Get and Record Task Commit SHA:**
    - **Step 9.1: Update Plan:** Read `plan.md`, find the line for the completed task, update its status from `[~]` to `[x]`, and append the first 7 characters of the *just-completed commit's* commit hash.
    - **Step 9.2: Write Plan:** Write the updated content back to `plan.md`.

10. **Commit Plan Update:**
    - **Action:** Stage the modified `plan.md` file.
    - **Action:** Commit this change with a descriptive message (e.g., `conductor(plan): Mark task 'Create user model' as complete`).

### Phase Completion Verification and Checkpointing Protocol

**Trigger:** This protocol is executed immediately after a task is completed that also concludes a phase in `plan.md`.

1. **Announce Protocol Start:** Inform the user that the phase is complete and the verification and checkpointing protocol has begun.

2. **Verify Test Coverage:**
   - Ensure all code files changed in this phase have corresponding tests.
   - Create missing tests following project conventions (`test_*.py` for Python).
   - Verify coverage meets requirements (60%+ global, 70%+ security).

3. **Execute Automated Tests:**
   - Run full test suite: `pytest --cov=app --cov=src --cov-report=term-missing`
   - If tests fail, debug and fix. If issues persist after 2 attempts, request user guidance.

4. **Manual Verification:**
   - For backend changes: Provide curl commands or API test steps.
   - For frontend changes: Provide browser testing steps with expected outcomes.
   - Keep verification steps concise and actionable.

5. **Await Explicit User Feedback:**
   - Ask: "Does this meet your expectations?"
   - Wait for user confirmation before proceeding.

6. **Create Checkpoint Commit:**
   - Stage all changes. If no changes occurred in this step, proceed with an empty commit.
   - Perform the commit with a clear and concise message (e.g., `conductor(checkpoint): Checkpoint end of Phase X`).

7. **Include Verification Summary in Commit Message:**
   - Include automated test command, manual verification steps, and verification outcome directly in the checkpoint commit message.
   - Follow structured commit format with detailed summary section.

8. **Get and Record Phase Checkpoint SHA:**
   - **Step 8.1: Get Commit Hash:** Obtain the hash of the *just-created checkpoint commit* (`git log -1 --format="%H"`).
   - **Step 8.2: Update Plan:** Read `plan.md`, find the heading for the completed phase, and append the first 7 characters of the commit hash in the format `[checkpoint: <sha>]`.
   - **Step 8.3: Write Plan:** Write the updated content back to `plan.md`.

9. **Commit Plan Update:**
   - **Action:** Stage the modified `plan.md` file.
   - **Action:** Commit this change with a descriptive message following the format `conductor(plan): Mark phase '<PHASE NAME>' as complete`.

10. **Announce Completion:** Inform the user that the phase is complete and the checkpoint has been created.

### Quality Gates

Before marking any task complete, verify:

- [ ] All tests pass
- [ ] Code coverage meets requirements (>60% global, 70%+ security)
- [ ] Code follows project's code style guidelines (as defined in `code_styleguides/`)
- [ ] All public functions/methods are documented (Docstrings follow standard Python conventions)
- [ ] Type safety is enforced (Type hints)
- [ ] No linting or static analysis errors (black, isort, flake8, mypy)
- [ ] Documentation updated if needed
- [ ] No security vulnerabilities introduced

## Development Commands

### Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Daily Development
```bash
# Run tests with coverage
pytest --cov=app --cov=src --cov-report=term-missing

# Linting and Formatting
black .
isort .
flake8 .
mypy .
```

### Before Committing
```bash
# Run pre-commit hooks
pre-commit run --all-files
```

## Testing Requirements

### Unit Testing
- Every module must have corresponding tests using `pytest`.
- Use `Hypothesis` for property-based testing where applicable.
- Use appropriate test setup/teardown (fixtures).
- Mock external dependencies.
- Test both success and failure cases.

### Integration Testing
- Test complete user flows (FastAPI/Flask TestClient)
- Verify database transactions (SQLAlchemy + PostgreSQL/SQLite)
- Test authentication and authorization (JWT)
- Check form submissions (multipart/form-data)

## Code Review Process

### Self-Review Checklist
Before requesting review:

1. **Functionality**
   - Feature works as specified
   - Edge cases handled
   - Error messages are user-friendly and sanitized

2. **Code Quality**
   - Follows style guide (python.md, javascript.md, html-css.md)
   - DRY principle applied
   - Clear variable/function names
   - Appropriate comments (Focus on "why")

3. **Testing**
   - Unit tests comprehensive
   - Integration tests pass
   - Coverage adequate (>60%)

4. **Security**
   - No hardcoded secrets
   - Input validation present
   - SQL injection prevented
   - XSS protection in place

5. **Performance**
   - Database queries optimized
   - Scapy PacketMetadata optimization utilized for large PCAPs

## Commit Guidelines

### Message Format
```
<TYPE> vX.Y.Z: <Description>

[Detailed task summary]

Technical details:
- Detail 1
- Detail 2

Modified files:
- file1.py
- file2.py
```

### Types
- `FEATURE`: New feature
- `BUGFIX`: Bug fix
- `DOCS`: Documentation only
- `STYLE`: Formatting, linting fixes
- `REFACTOR`: Code change that neither fixes a bug nor adds a feature
- `TEST`: Adding missing tests
- `SECURITY`: Security related fixes or features
- `CHORE`: Maintenance tasks

## Definition of Done

A task is complete when:

1. All code implemented to specification
2. Unit tests written and passing
3. Code coverage meets project requirements (>60%)
4. Documentation complete (if applicable)
5. Code passes all configured linting and static analysis checks
6. Implementation notes added to `plan.md`
7. Changes committed with proper structured message

## Deployment Workflow

### Pre-Deployment Checklist
- [ ] All tests passing
- [ ] Coverage >60%
- [ ] No linting errors
- [ ] Environment variables configured (.env)
- [ ] Database migrations ready (Alembic)
- [ ] Backup created


### Deployment Steps
1. Merge feature branch to main
2. Tag release with version
3. Push to deployment service
4. Run database migrations
5. Verify deployment
6. Test critical paths
7. Monitor for errors

### Post-Deployment
1. Monitor analytics
2. Check error logs
3. Gather user feedback
4. Plan next iteration

## Continuous Improvement

- Review workflow weekly
- Update based on pain points
- Document lessons learned
- Optimize for user happiness
- Keep things simple and maintainable
