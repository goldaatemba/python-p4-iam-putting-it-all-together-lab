"""Update User and Recipe models

Revision ID: 3633ec2e6d3f
Revises: 1a12a42695f4
Create Date: 2025-06-29 12:08:00.376151

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3633ec2e6d3f'
down_revision = '1a12a42695f4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('recipes', schema=None) as batch_op:
        batch_op.alter_column('minutes_to_complete',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('recipes', schema=None) as batch_op:
        batch_op.alter_column('minutes_to_complete',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###
