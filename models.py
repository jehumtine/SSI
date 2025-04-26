from pydantic import BaseModel
from typing import List, Union, Optional

class Passport(BaseModel):
    id: str
    name: str
    passport_number: str
    dob: str
    nationality: str
    issue_date: str
    expiry_date: str

class DriverLicense(BaseModel):
    id: str
    name: str
    license_number: str
    dob: str
    address: str
    issue_date: str
    expiry_date: str

class HealthInsurance(BaseModel):
    id: str
    name: str
    policy_number: str
    plan_type: str
    coverage_details: str
    start_date: str


Document = Union[Passport, DriverLicense, HealthInsurance]


class IdentityPackage(BaseModel):
    documents: List[Document]


class UserPackage(BaseModel):
    key: str
    package: str
