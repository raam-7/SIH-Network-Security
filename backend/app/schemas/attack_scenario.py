class AttackScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    status: AttackScenarioStatus
    severity: str
    supporting_rule_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    evidence_score: int = Field(default=0, ge=0, le=100)
    entry_point: str = "Network Management Plane"
    potential_path: list[str] = Field(default_factory=list)
    potential_impact: str
    recommended_controls: list[str] = Field(default_factory=list)
    requires_human_review: bool = False
