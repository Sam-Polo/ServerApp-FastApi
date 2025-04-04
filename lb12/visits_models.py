# visits_models.py:
from pydantic import BaseModel


class LessonSchema(BaseModel):
    date: str
    time: str
    type: str
    number: int
    subgroups: int
    visit: bool


class StudentSchema(BaseModel):
    name: str
    subgroup: int
    lessons: list[LessonSchema]
    visit_percent: float
    success_labs_percent: float
    success_labs: int
    result: bool


class GroupResultSchema(BaseModel):
    success: str
    unsuccessfully: str


class GroupSchema(BaseModel):
    group_name: str
    students: list[StudentSchema]
    result: GroupResultSchema


class VisitsResponseSchema(BaseModel):
    groups: list[GroupSchema]
