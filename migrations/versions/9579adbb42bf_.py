"""empty message

Revision ID: 9579adbb42bf
Revises: 417ea1b1b8fe
Create Date: 2020-04-13 18:37:37.583285

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9579adbb42bf'
down_revision = '417ea1b1b8fe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('userauths', sa.Column('biometric_id', sa.String(length=100), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('userauths', 'biometric_id')
    # ### end Alembic commands ###
