# visits_controller.py:
import pandas as pd
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException

from db import SessionDep
from auth_controller import require_permission
from models import UserModel
from lb12.visits_models import VisitsResponseSchema, GroupSchema, StudentSchema, LessonSchema, GroupResultSchema


router = APIRouter(prefix='/visits', tags=['Посещаемость'])


@router.post('/check', response_model=VisitsResponseSchema)
async def check_visits(
        file: UploadFile = File(...),
        current_user: UserModel = Depends(require_permission('check-visits'))):
    """
    Проверяет посещаемость студентов и определяет, кто получает зачёт автоматом.
    Принимает файл посещаемости и возвращает json с результатами.
    """
    # проверяем, что файл — csv или excel
    if file.content_type not in ['text/csv', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
        raise HTTPException(status_code=400, detail='Файл должен быть в формате csv или excel')

    # читаем файл в dataframe
    try:
        if file.content_type == 'text/csv':
            df = pd.read_csv(file.file, encoding='cp1251')
        else:  # excel
            df = pd.read_excel(file.file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Ошибка чтения файла: {str(e)}')

    # приводим столбцы к нижнему регистру для удобства
    df.columns = df.columns.str.lower()

    # проверяем наличие необходимых столбцов
    required_columns = {'student', 'group', 'date', 'time', 'type', 'number', 'subgroups', 'visit'}
    if not required_columns.issubset(df.columns):
        raise HTTPException(status_code=400, detail='В файле отсутствуют необходимые столбцы')

    # обрабатываем данные
    groups = {}
    for _, row in df.iterrows():
        group_name = row['group']
        student_name = row['student']
        subgroup = row.get('subgroup', 1) if pd.notna(row.get('subgroup')) else 1  # по умолчанию 1-я подгруппа

        if group_name not in groups:
            groups[group_name] = {}

        if student_name not in groups[group_name]:
            groups[group_name][student_name] = {'subgroup': subgroup, 'lessons': []}

        # парсим подгруппы занятия (например, "1,2" → [1, 2])
        subgroups = [int(s) for s in str(row['subgroups']).split(',') if s.isdigit()]

        # добавляем занятие
        lesson = LessonSchema(
            date=str(row['date']),
            time=str(row['time']),
            type=str(row['type']),
            number=int(row['number']),
            subgroups=subgroups[0] if len(subgroups) == 1 else subgroups,  # упрощение для вывода
            visit=bool(row['visit'])
        )
        groups[group_name][student_name]['lessons'].append(lesson)

    # расчёт результатов
    result = []
    for group_name, students_data in groups.items():
        students = []
        success_count = 0
        unsuccess_count = 0

        for student_name, data in students_data.items():
            lessons = data['lessons']
            subgroup = data['subgroup']

            # собственные занятия студента (где его подгруппа совпадает)
            own_lessons = [l for l in lessons if isinstance(l.subgroups, int) and l.subgroups == subgroup or 
                          (isinstance(l.subgroups, list) and subgroup in l.subgroups)]
            total_own_lessons = len(own_lessons)
            visited_own_lessons = sum(1 for l in own_lessons if l.visit)

            # все посещения (включая чужие подгруппы)
            total_visits = sum(1 for l in lessons if l.visit)

            # лабораторные
            labs = [l for l in lessons if l.type == 'lab']
            total_labs = len(labs)
            success_labs = sum(1 for l in labs if l.visit)

            # расчёт процентов
            visit_percent = (total_visits / total_own_lessons * 100) if total_own_lessons > 0 else 0
            success_labs_percent = (success_labs / total_labs * 100) if total_labs > 0 else 0

            # условие зачёта: 80% посещаемости и минимум 50% лаб
            is_passed = visit_percent >= 80 and success_labs_percent >= 50

            student = StudentSchema(
                name=student_name,
                subgroup=subgroup,
                lessons=lessons,
                visit_percent=round(visit_percent, 2),
                success_labs_percent=round(success_labs_percent, 2),
                success_labs=success_labs,
                result=is_passed
            )
            students.append(student)
            if is_passed:
                success_count += 1
            else:
                unsuccess_count += 1

        group = GroupSchema(
            group_name=group_name,
            students=students,
            result=GroupResultSchema(success=str(success_count), unsuccessfully=str(unsuccess_count))
        )
        result.append(group)

    return VisitsResponseSchema(groups=result)
