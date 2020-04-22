"""empty message

Revision ID: a29712021345
Revises: 
Create Date: 2020-04-08 12:22:55.089883

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a29712021345'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('auth_codes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('phone', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Text(), nullable=False),
    sa.Column('activation', sa.Integer(), nullable=True),
    sa.Column('auth_status', sa.Integer(), nullable=False),
    sa.Column('creation_date', sa.TIMESTAMP(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('phone', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=True),
    sa.Column('full_name', sa.String(length=200), nullable=True),
    sa.Column('password', sa.Text(), nullable=True),
    sa.Column('pin', sa.Text(), nullable=True),
    sa.Column('device_id', sa.Text(), nullable=False),
    sa.Column('lat', sa.Float(), nullable=True),
    sa.Column('log', sa.Float(), nullable=True),
    sa.Column('photo', sa.String(length=100), nullable=True),
    sa.Column('level', sa.Integer(), nullable=True),
    sa.Column('activation', sa.Integer(), nullable=True),
    sa.Column('recovery_phone', sa.Integer(), nullable=True),
    sa.Column('status', sa.Integer(), nullable=True),
    sa.Column('creation_date', sa.TIMESTAMP(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('full_name')
    )
    op.create_table('unlinklogs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('phone', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Text(), nullable=False),
    sa.Column('unlink_date', sa.TIMESTAMP(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('userauths',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('biometric_status', sa.Integer(), nullable=True),
    sa.Column('fa2_status', sa.Boolean(), nullable=True),
    sa.Column('pin_status', sa.Integer(), nullable=True),
    sa.Column('password_status', sa.Integer(), nullable=True),
    sa.Column('phone_verify_status', sa.Integer(), nullable=True),
    sa.Column('biometric_photo', sa.String(length=100), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('userlogs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.Text(), nullable=False),
    sa.Column('lat', sa.Float(), nullable=True),
    sa.Column('log', sa.Float(), nullable=True),
    sa.Column('log_status', sa.Integer(), nullable=False),
    sa.Column('log_date', sa.TIMESTAMP(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('userlogs')
    op.drop_table('userauths')
    op.drop_table('unlinklogs')
    op.drop_table('users')
    op.drop_table('auth_codes')
    # ### end Alembic commands ###
