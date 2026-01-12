# Commit Guide

All team members must follow this guide to maintain a clean, readable, and organized commit history.

---

## 1. Clone the Repository
Each team member must begin by cloning the central repository to their local system.

- Do **not** work directly on the remote repository.
- All changes should be made locally first.

---

## 2. Create Your Own Branch
After cloning the repository:

- Create a **personal branch** from the `master` branch.
- Each team member must work **only on their own branch**.
- There are four members in the group, so there will be four separate branches.

> ⚠️ **Important:**
> No one should push directly to the `master` branch under any circumstances.

---

## 3. Work Only on Your Branch
- All development, edits, and updates must be done on your personal branch.
- Pull the latest changes from `master` periodically to stay up to date.
- Resolve conflicts within your branch if needed.

---

## 4. Making Commits
When committing changes:

- Commit **small and meaningful changes** rather than large unrelated updates.
- Make commits **frequently** to track progress clearly.
- Avoid committing broken or incomplete work unless necessary.

---

## 5. Commit Message Guidelines
Commit messages should be:
- **Descriptive** – clearly explain what was changed
- **Readable** – easy for others to understand
- **Concise** – short but informative

### Good Commit Message Examples
- `Add initial data preprocessing pipeline`
- `Update README with project overview`
- `Fix incorrect attack label mapping`
- `Improve explanation text clarity`

### Bad Commit Message Examples
- `update`
- `changes`
- `final`
- `stuff`

---

## 6. Pushing Changes
- Push commits **only to your personal branch**
- Never push directly to `master`
- Ensure your branch is stable before pushing

---

## 7. Keeping Commit History Clean
To maintain a clean repository:
- Avoid unnecessary commits
- Do not commit temporary or experimental files
- Write clear commit messages
- Keep commits logically separated

A clean commit history helps everyone understand the project evolution and simplifies collaboration.

---

## 8. Merging to Master
- Merging into `master` will be done **only after team discussion**
- Merges should be reviewed and approved by the team
- No direct commits to `master` are allowed

---

## Summary
- Clone the repository
- Create your own branch from `master`
- Work and commit only on your branch
- Write clear and descriptive commit messages
- Push only to your branch
- Keep the commit history clean and organized

Following this guide ensures smooth collaboration and project stability.

---

## Overview of Clarinet
This project presents an AI-driven system designed to identify different types of cyberattacks from network traffic data and explain its decisions in clear, human-readable language. The system combines network traffic analysis with explainable artificial intelligence to improve transparency and usability in cybersecurity monitoring environments such as Security Operations Centers (SOCs).

---

## Dataset Handling
The system uses publicly available intrusion detection datasets such as **CICIDS2017** and **NSL-KDD**, which contain real-world network traffic labeled as normal or malicious activity.

### How the Data Is Handled
- Raw network traffic records are collected from dataset files.
- Incomplete, duplicate, or inconsistent records are removed to maintain data quality.
- Network traffic attributes are standardized into a uniform structure.
- Traffic samples are grouped into predefined categories such as **Normal**, **DoS**, **DDoS**, **Port Scan**, and **Probe**.
- Processed data is stored in a reusable format to ensure reproducibility across experiments.

This approach ensures that the learning system is trained on clean, balanced, and representative network traffic data.

---

## System Implementation Flow
The project follows a structured, multi-stage pipeline:

1. **Input Stage**
   Network traffic data is provided to the system in a structured file format.

2. **Preprocessing Stage**
   The input data is cleaned, normalized, and prepared for analysis.

3. **Threat Classification Stage**
   The system analyzes the processed data and classifies the traffic as normal or malicious, assigning an appropriate attack category when applicable.

4. **Explanation Generation Stage**
   For each prediction, the system identifies influential traffic characteristics and converts them into concise natural language explanations.

5. **Output Stage**
   The final output includes:
   - The predicted traffic category
   - A human-readable explanation describing the reasoning behind the prediction

---

## Explainability Focus
Instead of producing only a classification label, the system emphasizes interpretability:
- Key traffic patterns influencing the decision are highlighted.
- These patterns are translated into short textual explanations.
- This allows users to understand why a particular alert was generated.

---

## Integrated Application
All components are combined into a single application workflow:
- Users provide network traffic data as input.
- The system returns both the predicted attack type and an explanation.
- The design supports easy testing, demonstration, and future extensions.

---

## Summary
This project demonstrates how network traffic data can be systematically handled, analyzed, and explained using AI-based approaches. By combining threat classification with human-readable explanations, the system highlights the importance of transparency and trust in modern cybersecurity solutions.